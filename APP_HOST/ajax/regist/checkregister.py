"""
Starter endpoint for early authentication RE work.

Replace the placeholder response as soon as the client logs reveal the exact
fields it requires.
"""

def handle(ctx):
    print("[checkregister] request:")
    print(ctx.data_plaintext)

    return ctx.api_json({
        "error": 0,
        "result": {}
    })
