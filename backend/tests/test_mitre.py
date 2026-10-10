from src.mitre.mitre_mapping import MitreMapper


mapper = MitreMapper()


result = mapper.get_mapping(
    "DDoS"
)


print(result)