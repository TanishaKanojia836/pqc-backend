from app.models import EncryptionAlgorithm, RiskLevel

def calculate_quantum_risk(algorithm: EncryptionAlgorithm, key_size: int, is_public: bool) -> tuple[float, RiskLevel]:
    """
    Calculates quantum vulnerability score (0.0 - 100.0) and Risk Level.
    Shor's Algorithm breaks RSA/ECC easily, while Grover's impacts AES mildly.
    PQC algorithms (Kyber, Dilithium) are quantum-safe.
    """
    base_score = 0.0

    if algorithm in [EncryptionAlgorithm.RSA, EncryptionAlgorithm.ECC]:
        base_score = 90.0 if key_size < 3072 else 75.0
    elif algorithm == EncryptionAlgorithm.AES_128:
        base_score = 50.0
    elif algorithm == EncryptionAlgorithm.AES_256:
        base_score = 20.0
    elif algorithm in [EncryptionAlgorithm.KYBER_768, EncryptionAlgorithm.DILITHIUM]:
        base_score = 5.0

    if is_public:
        base_score = min(100.0, base_score + 10.0)

    if base_score >= 70.0:
        level = RiskLevel.HIGH
    elif base_score >= 35.0:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return round(base_score, 1), level
