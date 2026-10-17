"""QR code as an inline SVG data URI.

Uses python3-qrcode-core only for the module matrix (get_matrix), and draws the
SVG here, so no imaging library is needed.
"""

import base64


def matrix_to_svg(matrix, scale=6):
    size = len(matrix)
    parts = []
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                parts.append("M%d %dh1v1h-1z" % (x, y))
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d"'
            ' shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/>'
            '<path fill="#000" d="%s"/></svg>' % (size, size, size * scale, size * scale, "".join(parts)))


def qr_data_uri(text):
    import qrcode
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    svg = matrix_to_svg(qr.get_matrix())
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("ascii")).decode("ascii")
