class FrequencyAnalyzer:
    """
    Analyse la fréquence des événements
    dans le dataset CICIDS.
    """

    def __init__(self, dataset):
        self.dataset = dataset


    def get_frequency(self, source_ip, attack_type):
        """
        Retourne le nombre d'occurrences
        d'une attaque provenant d'une IP donnée.
        """

        filtered = self.dataset[
            (self.dataset[" Source IP"] == source_ip)
            &
            (self.dataset[" Label"] == attack_type)
        ]

        return len(filtered)