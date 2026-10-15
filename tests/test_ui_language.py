"""Prevent Indonesian-language operator text from returning in KAORI UI.

The same English-only convention covers scripts, terminal reports and operator
documentation. The vocabulary is deliberately limited to Indonesian-only words
or phrases to avoid rejecting technical English tokens.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Add new expressions as they are discovered during manual copy review.
INDONESIAN_MARKERS = (
    "catatan", "keterangan", "keluarga", "eksekusi", "contoh", "penjelasan",
    "perhatian", "peringatan", "berhasil", "gagal", "kesalahan", "tidak",
    "sudah", "belum", "pilih", "terpilih", "dengan", "untuk", "dari",
    "pada", "yang", "masih", "atau", "jika", "maka", "akan", "berikut",
    "sebelum", "sesudah", "periksa", "hasil", "jumlah", "sertifikat",
    "kedaluwarsa", "diperbarui", "dibuat", "dihapus", "ditemukan",
    "menunggu", "ditolak", "harus", "dapat", "sebagai", "simpan",
    "disimpan", "menggunakan", "melalui", "tambahkan", "masukkan",
    "batal", "kembali", "lanjut", "semua", "pengaturan", "ringkasan",
    "rincian", "pengguna", "penyimpanan", "rahasia", "kunci",
    "sekarang", "tunggu", "hanya", "tanpa", "terhadap", "tetap",
    "memiliki", "masalah", "wajib", "dibutuhkan", "dianggap",
    "misalnya", "tentang", "perlu", "aktif", "terakhir",
    "kemudian", "ketika", "silakan", "berkas", "berlaku",
    "berikutnya", "perubahan", "pembaruan", "penyelesaian",
    "pilihan", "tampilan", "tujuan", "petunjuk", "lakukan",
    "terdapat", "sejumlah", "ditambahkan", "penyebab",
    "proses", "keamanan", "berisiko", "konfirmasi", "dijalankan",
    "terhubung", "dilengkapi", "tersedia", "dibutuhkan",
)
PATTERN = re.compile(
    r"(?<![A-Za-z])(?:" + "|".join(
        re.escape(item) for item in sorted(set(INDONESIAN_MARKERS), key=len, reverse=True)
    ) + r")(?![A-Za-z])",
    flags=re.IGNORECASE,
)


def violations(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return [f"{path.relative_to(ROOT)}:{number}: {match.group(0)}"
            for number, line in enumerate(lines, 1)
            for match in PATTERN.finditer(line)]


class EnglishOnlyUserInterfaceTests(unittest.TestCase):
    def test_keyword_guard_detects_real_non_english_phrases(self):
        for example in ("Catatan: SAN changed",
                        "Status eksekusi:",
                        "Detail keluarga certificate"):
            self.assertIsNotNone(PATTERN.search(example))

    def test_scripts_have_no_indonesian_language_markers(self):
        scripts = sorted(p for p in (ROOT / "scripts").rglob("*")
                         if p.is_file() and p.suffix in {".py", ".sh"})
        self.assertGreaterEqual(len(scripts), 8)
        findings = [item for path in scripts for item in violations(path)]
        self.assertEqual(findings, [], "Non-English source text: " + ", ".join(findings))

    def test_operator_documentation_has_no_indonesian_language_markers(self):
        docs = [ROOT / "README.md", ROOT / "SECURITY.md"]
        docs += sorted((ROOT / "docs").rglob("*.md"))
        findings = [item for path in docs for item in violations(path)]
        self.assertEqual(findings, [], "Non-English docs: " + ", ".join(findings))


if __name__ == "__main__":
    unittest.main()
