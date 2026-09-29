"""
Auto-created Dragon Project endpoint.
Route: /APP_HOST/ajax/pushnotification/device/post
Edit handle(ctx). The receiver reloads this file for every request.
"""

def handle(ctx):
    print("[STUB] /APP_HOST/ajax/pushnotification/device/post")
    print("request data:", ctx.data_plaintext)

    return ctx.api_json({
        "error": 0,
        "result": {}
    })
