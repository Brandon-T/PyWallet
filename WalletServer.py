from APNS import APNS
from Wallet import Sign
import json
import calendar
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

from OpenSSL import Signing
from hashlib import md5
from flask import Flask, request, Response

import threading


#Setup Server and Database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../Databases/AppleWalletTest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Models
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(80))
    uuid = db.Column(db.String(128))
    push_token = db.Column(db.String(128))
    pass_type_id = db.Column(db.String(64))
    serial_number = db.Column(db.String(64))
    registration_date = db.Column(db.Integer)

    def __init__(self, device_id, uuid, push_token, pass_type_id, serial_number, registration_date=None):
        self.device_id = device_id
        self.uuid = uuid
        self.push_token = push_token
        self.pass_type_id = pass_type_id
        self.serial_number = serial_number
        self.registration_date = registration_date if registration_date is not None else calendar.timegm(datetime.utcnow().utctimetuple())

    def __repr__(self):
        return json.dumps({"Device": {"id": self.id,
                                      "device_id": self.device_id,
                                      "uuid": self.uuid,
                                      "push_token": self.push_token,
                                      "pass_type_id": self.pass_type_id,
                                      "serial_number": self.serial_number,
                                      "registration_date": self.registration_date}
                           }, indent=4, sort_keys=False, separators=(",", ":"))

class Pass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(64))
    auth_token = db.Column(db.String(128))
    pass_type_id = db.Column(db.String(64))
    pass_json = db.Column(db.Text)
    last_updated = db.Column(db.Integer)

    def __init__(self, serial_number, auth_token, pass_type_id, pass_json, last_updated=None):
        self.serial_number = serial_number
        self.auth_token = auth_token
        self.pass_type_id = pass_type_id
        self.pass_json = pass_json
        self.last_updated = last_updated if last_updated is not None else calendar.timegm(datetime.utcnow().utctimetuple())

    def __repr__(self):
        return json.dumps({"Pass": {"id": self.id,
                                    "serial_number": self.serial_number,
                                    "auth_token": self.auth_token,
                                    "pass_type_id": self.pass_type_id,
                                    "pass_json": self.pass_json,
                                    "last_updated": self.last_updated}
                           }, indent=4, sort_keys=False, separators=(",", ":"))


#Server Endpoints
def make_response(code, data, contenttype=None, headers=None):
    return Response(response=data, status=code, headers=headers, mimetype=None, content_type=contenttype)

def strip_validate_authToken(token):
    return token.replace("ApplePass ", "") if token is not None and "ApplePass " in token else None

def flatten_tuple(tuple):
    res = []
    for (item) in tuple:
        res.extend(item)
    return res




# Register Devices for pass-book notifications
@app.route("/wallet/<version>/devices/<deviceLibraryIdentifier>/registrations/<passTypeIdentifier>/<serialNumber>", methods=["POST"])
def registerWallet(version, deviceLibraryIdentifier, passTypeIdentifier, serialNumber):
    if version == "v1":
        authToken = strip_validate_authToken(request.headers.get("Authorization"))

        if authToken:
            if Pass.query.filter_by(serial_number=serialNumber, auth_token=authToken).count() > 0:
                uuid = deviceLibraryIdentifier + "-" + serialNumber

                if Device.query.filter_by(uuid=uuid).count() < 1:
                    jsonData = request.get_json(silent=False)
                    device = Device(deviceLibraryIdentifier, uuid, jsonData["pushToken"], passTypeIdentifier, serialNumber)
                    db.session.add(device)
                    db.session.commit()
                    return make_response(201, "Successfully Registered")

                return make_response(200, "Already Registered")

        return make_response(401, "Unauthorized User")

    return make_response(404, "Unsupported Pass Version")


# Unregister devices for passbook-notifications
@app.route("/wallet/<version>/devices/<deviceLibraryIdentifier>/registrations/<passTypeIdentifier>/<serialNumber>", methods=["DELETE"])
def unregisterWallet(version, deviceLibraryIdentifier, passTypeIdentifier, serialNumber):
    if version == "v1":
        authToken = strip_validate_authToken(request.headers.get("Authorization"))

        if authToken:
            if Pass.query.filter_by(serial_number=serialNumber, auth_token=authToken).count() > 0:
                uuid = deviceLibraryIdentifier + "-" + serialNumber

                if Device.query.filter_by(uuid=uuid).count() > 0:
                    Device.query.filter_by(uuid=uuid).delete()
                    db.session.commit()
                    return make_response(200, "Successfully Unregistered")

                return make_response(401, "Device doesn't exist")


        return make_response(401, "Unauthorized User")

    return make_response(404, "Unsupported Pass Version")


# Get all passes that need updating
@app.route("/wallet/<version>/devices/<deviceLibraryIdentifier>/registrations/<passTypeIdentifier>", methods=["GET"])
def getUpdatedPasses(version, deviceLibraryIdentifier, passTypeIdentifier):
    if version == "v1":
        if Device.query.filter_by(device_id=deviceLibraryIdentifier).count() > 0:
            serialNumbers = flatten_tuple(db.session.query(Device.serial_number).filter_by(device_id=deviceLibraryIdentifier, pass_type_id=passTypeIdentifier).all())

            updatedSinceDate = request.args.get("passesUpdatedSince")

            if updatedSinceDate is not None and len(updatedSinceDate):
                serialNumbers = flatten_tuple(db.session.query(Pass.serial_number).filter(Pass.serial_number.in_(serialNumbers)).filter(Pass.last_updated >= int(updatedSinceDate)).all())
            else:
                serialNumbers = flatten_tuple(db.session.query(Pass.serial_number).filter(Pass.serial_number.in_(serialNumbers)).all())

            if len(serialNumbers) > 0:
                time_stamp = calendar.timegm(datetime.utcnow().utctimetuple())
                resp_data = json.dumps({"lastUpdated": str(time_stamp),
                                        "serialNumbers": serialNumbers
                                        }, indent=4, sort_keys=False, separators=(",", ":"))
                return make_response(200, resp_data, "application/json", headers={"last-modified": str(time_stamp)})
            else:
                return make_response(204, "No updates available")
        else:
            return make_response(404, "Device not registered")

    return make_response(404, "Unsupported Pass Version")


@app.route("/wallet/<version>/passes/<passTypeIdentifier>/<serialNumber>", methods=["GET"])
def getLatestPass(version, passTypeIdentifier, serialNumber):
    if version == "v1":
        authToken = strip_validate_authToken(request.headers.get("Authorization"))
        if authToken:
            if Pass.query.filter_by(serial_number=serialNumber, pass_type_id=passTypeIdentifier, auth_token=authToken).count() > 0:
                hasNewPass = True
                modified_since = request.headers.get("if-modified-since")

                if modified_since is not None and len(modified_since):
                    hasNewPass = db.session.query(Pass).filter(Pass.last_updated >= int(modified_since)).count() > 0

                if hasNewPass:
                    file = open("../Passes/ScenePass.pkpass", "rb")
                    data = file.read()
                    file.close()

                    time_stamp = calendar.timegm(datetime.utcnow().utctimetuple())
                    return make_response(200, data, "application/vnd.apple.pkpass", headers={"last-modified": str(time_stamp)})

                return make_response(304, "No updates available")

        return make_response(401, "Unauthorized User")

    return make_response(404, "Unsupported Pass Version")


@app.route("/wallet/<version>/log", methods=["POST"])
def logWallet(version):
    jsonData = request.get_json(silent=False)
    print(json.dumps(jsonData, indent=4, sort_keys=False, separators=(",", ":")) + "\n\n")
    return make_response(200, "Successfully Logged")


@app.route("/wallet/generatePassForUser", methods=["GET", "POST"])
def generatePassForUser():  #TODO Authentication request.. Used AuthToken, etc..
    requestJSON = request.get_json(silent=False)

    #Just for testing if using GET requests to download the pass..
    if requestJSON is None:
        requestJSON = {
            "cardNumber": "6046463399374746",
            "firstName": "Brandon",
            "lastName": "Test",
            "points": "925",
            "member_date": "09/17"
        }

    if requestJSON is not None:
        cardNumber = requestJSON.pop("cardNumber", None)
        firstName = requestJSON.pop("firstName", None)
        lastName = requestJSON.pop("lastName", None)
        points = requestJSON.pop("points", None)
        date = requestJSON.pop("member_date", None)

        #TODO: Check that all fields exist.
        pkpass = Sign.PKPass("../Passes/ScenePass.pass")
        passJSON = json.loads(pkpass.readJSON())
        passJSON["authenticationToken"] = md5(cardNumber.encode("utf-8")).hexdigest()  #md5(uuid4().bytes).hexdigest()
        passJSON["storeCard"]["headerFields"][0]["value"] = points
        passJSON["storeCard"]["secondaryFields"][0]["value"] = firstName + " " + lastName
        passJSON["storeCard"]["auxiliaryFields"][0]["value"] = date
        passJSON["barcode"]["message"] = cardNumber
        passJSON["barcode"]["altText"] = cardNumber
        passJSON["serialNumber"] = cardNumber
        pkpass.writeJSON(json.dumps(passJSON, ensure_ascii=False, separators=(",", ":"), indent=4, sort_keys=False))

        pkpass.sign("../PassCerts/PassKit.p12", "../PassCerts/AppleWWDR.pem", "123")
        pkpass.compress("../Passes/ScenePass.pkpass")

        Pass.query.filter_by(serial_number=cardNumber).delete()
        db.session.commit()

        storePass = Pass(serial_number=passJSON["serialNumber"],
                         auth_token=passJSON["authenticationToken"],
                         pass_type_id=passJSON["passTypeIdentifier"],
                         pass_json=json.dumps(passJSON, ensure_ascii=False, separators=(",", ":"), indent=0, sort_keys=False))
        db.session.add(storePass)
        db.session.commit()

        thread = threading.Thread(name="updateFakePassThread", target=updateFakePassForUser, args=(cardNumber,))
        thread.start()

    return make_response(200, json.dumps(passJSON, ensure_ascii=False, separators=(",", ":"), indent=4, sort_keys=False), "application/json")

@app.route("/wallet/fakeUpdate/<cardNumber>", methods=["GET", "POST"])
def updateFakePassForUser(cardNumber):
    auth_token = md5(cardNumber.encode("utf-8")).hexdigest()
    passes = Pass.query.filter(Pass.serial_number == cardNumber, Pass.auth_token == auth_token).all()
    for ps in passes:
        ps.last_updated = calendar.timegm(datetime.utcnow().utctimetuple())
    db.session.commit()

    apns = APNS.APNS(sandbox=False, use_certificate=False)
    tokens = flatten_tuple(db.session.query(Device.push_token).filter(Device.device_id).all())

    for token in tokens:
        response = apns.push(token, "pass.com.scene.test", json.dumps({"aps":{}}, cls=None, ensure_ascii=False, separators=(',', ':')))
        print(response.read().decode("utf-8"))

    return make_response(200, "Success")

def run():
    Signing.initializeOpenSSL()
    #db.drop_all()  #TODO: Add Migration
    db.create_all()
    app.run("0.0.0.0", port=5000)
