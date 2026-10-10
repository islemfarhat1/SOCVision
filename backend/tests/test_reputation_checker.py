from src.threat_intelligence.reputation_checker import ReputationChecker


checker = ReputationChecker()


result = checker.check_ip(
    "172.16.0.1"
)


print(result)