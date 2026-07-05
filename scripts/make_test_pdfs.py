from pathlib import Path


OUT_DIR = Path("samples")


def pdf_escape(text: str) -> str:
    return (
        text
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def write_pdf(
    path: Path,
    body_text: str,
    javascript: str | None = None,
    raw_comment: bytes | None = None,
) -> None:
    body_text = pdf_escape(body_text)

    objects: list[bytes] = []

    catalog_extra = ""
    if javascript is not None:
        catalog_extra = " /OpenAction 5 0 R"

    objects.append(
        f"<< /Type /Catalog /Pages 2 0 R{catalog_extra} >>".encode()
    )

    objects.append(
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
    )

    objects.append(
        b"<< /Type /Page /Parent 2 0 R "
        b"/MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> "
        b"/Contents 6 0 R >>"
    )

    objects.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    )

    if javascript is not None:
        js = pdf_escape(javascript)
        objects.append(
            f"<< /S /JavaScript /JS ({js}) >>".encode()
        )

    content = (
        "BT\n"
        "/F1 18 Tf\n"
        "72 720 Td\n"
        f"({body_text}) Tj\n"
        "ET\n"
    ).encode()

    objects.append(
        b"<< /Length " + str(len(content)).encode() + b" >>\n"
        b"stream\n" + content + b"endstream"
    )

    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")
    pdf.extend(b"% minimal test pdf\n")

    # ВАЖНО:
    # PDF comments начинаются с %, но байты всё равно лежат в файле.
    # ClamAV увидит EICAR как raw bytes.
    if raw_comment:
        pdf.extend(b"% ")
        pdf.extend(raw_comment)
        pdf.extend(b"\n")

    offsets = [0]

    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{idx} 0 obj\n".encode())
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)

    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    pdf.extend(b"0000000000 65535 f \n")

    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())

    pdf.extend(
        b"trailer\n"
        + f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
        + b"startxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )

    path.write_bytes(bytes(pdf))


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    write_pdf(
        OUT_DIR / "clean.pdf",
        "Clean PDF: no JavaScript, no active action.",
    )

    write_pdf(
        OUT_DIR / "js_action.pdf",
        "PDF with benign JavaScript OpenAction.",
        javascript="app.alert('Benign test JavaScript action');",
    )

    eicar = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
        b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    write_pdf(
        OUT_DIR / "eicar.pdf",
        "EICAR test signature inside PDF comment.",
        raw_comment=eicar,
    )

    print("Generated:")
    print("  samples/clean.pdf")
    print("  samples/js_action.pdf")
    print("  samples/eicar.pdf")


if __name__ == "__main__":
    main()