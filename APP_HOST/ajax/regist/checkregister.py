"""
Dragon Project 1.8.9 dummy checkregister response.

This is intentionally a bootstrap-only account. It does not perform
real authentication or create the permanent client-side userHash.
"""

def handle(ctx):
    print("[checkregister] request:")
    print("  plaintext:", ctx.data_plaintext)
    print("  device:", (ctx.data_json or {}).get("d", ""))

    return ctx.api_json({
        "error": 0,

        # Values consumed by BaseModel.Apply().
        "currentTime": "2026-09-29 00:00:00",
        "assetManifestVersion": 1,
        "assetIndex": 7,
        "tableIndex": 1,
        "tableManifestVersion": 1,

        # Development mode:
        # DataTableManager.reportOnly == true, allowing unsigned
        # table files to pass verification.
        "vm": 1,

        "appClose": False,
        "usageLimitMode": False,
        "closedNotice": "",
        "openRefundForm": False,

        "result": {
            "uh": "",
            "userId": 1,
            "userIdHash": "dummy-user-1",

            "userInfo": {
                "id": 1,
                "name": "/colopl_rob",
                "comment": "",
                "lastLogin": "",
                "isParentPassSet": 0,
                "isStopperSet": 0,
                "isAdvancedUser": False,
                "isAdvancedUserGoogle": False,
                "isAdvancedUserFacebook": False,
                "isSetGooglePassword": False,
                "advancedUserMail": "",
                "code": "dummy-user-1",
                "inputInviteFlag": False,
                "birthday": "",
                "communityFlag": False,
                "codeDispFlag": True,
                "pushEnable": 0,
                "editNameAt": {},
                "constDefine": {
                    "cdv": 1540274801,
                    "ALIVE_CHECK_SEC": 270
                },
                "isCharged": False
            },

            "newsId": 1,
            "tutorialStep": 0,
            "sendAsset": False,
            "termsCheck": False,
            "termsUpdateDay": "",
            "recommendUpdate": False
        }
    })