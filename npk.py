import io
import struct
import hashlib
from enum import IntEnum


class NpkPartID(IntEnum):
    HEADER = 1
    CONTENT = 2
    SIGNATURE_KCDSA = 3
    SIGNATURE_EDDSA = 4


class NpkFileContainer:
    def __init__(self, part_id, data):
        self.part_id = part_id
        self.data = data

    def get_bytes(self):
        length = len(self.data)
        return struct.pack(">II", self.part_id, length) + self.data


class NovaPackage:
    def __init__(self):
        self.parts = []

    @classmethod
    def from_file(cls, filename):
        with open(filename, "rb") as f:
            data = f.read()
        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data):
        pkg = cls()
        stream = io.BytesIO(data)

        while True:
            header = stream.read(8)
            if len(header) < 8:
                break
            part_id, length = struct.unpack(">II", header)
            part_data = stream.read(length)
            pkg.parts.append(NpkFileContainer(part_id, part_data))

        return pkg

    def get_part(self, part_id):
        for part in self.parts:
            if part.part_id == part_id:
                return part
        return None

    def replace_part(self, part_id, data):
        for i, part in enumerate(self.parts):
            if part.part_id == part_id:
                self.parts[i] = NpkFileContainer(part_id, data)
                return
        # Kalau part belum ada, tambahkan
        self.parts.append(NpkFileContainer(part_id, data))

    def get_bytes(self):
        return b"".join([part.get_bytes() for part in self.parts])

    def save(self, filename):
        with open(filename, "wb") as f:
            f.write(self.get_bytes())

    def sign(self, kcdsa_private_key, eddsa_private_key):
        """
        Membuat signature KCDSA dan EDDSA.
        Signature dihitung dari hash SHA-256 pada semua part kecuali signature.
        """
        sha256 = hashlib.sha256()

        for part in self.parts:
            if part.part_id not in (NpkPartID.SIGNATURE_KCDSA, NpkPartID.SIGNATURE_EDDSA):
                sha256.update(part.get_bytes())

        sha256_digest = sha256.digest()

        # KCDSA signature
        from mikro import mikro_kcdsa_sign
        kcdsa_signature = mikro_kcdsa_sign(sha256_digest[:20], kcdsa_private_key)
        self.replace_part(NpkPartID.SIGNATURE_KCDSA, kcdsa_signature)

        # EDDSA signature
        from mikro import mikro_eddsa_sign
        eddsa_signature = mikro_eddsa_sign(sha256_digest, eddsa_private_key)
        self.replace_part(NpkPartID.SIGNATURE_EDDSA, eddsa_signature)


if __name__ == "__main__":
    # Contoh penggunaan
    pkg = NovaPackage.from_file("input.npk")
    print("Part tersedia:", [p.part_id for p in pkg.parts])
    pkg.save("output_copy.npk")
