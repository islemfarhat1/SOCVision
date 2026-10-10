import pandas as pd
from pathlib import Path

from src.models.network_flow import NetworkFlow


class CICIDSSimulator:

    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.data = None

    def load_dataset(self):
        path = Path(self.dataset_path)

        if path.is_dir():
            self.data = self._load_multiple(path)
        else:
            self.data = self._read_csv_safe(path)

        return self.data

    def _load_multiple(self, folder: Path) -> pd.DataFrame:
        """Charge tous les CSV d'un dossier et les concatène."""
        csv_files = sorted(folder.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"Aucun CSV trouvé dans {folder}")

        frames = []
        for f in csv_files:
            df = self._read_csv_safe(f)
            df["source_file"] = f.name
            frames.append(df)
            print(f"[OK] {f.name} : {len(df)} lignes")

        return pd.concat(frames, ignore_index=True)

    def _read_csv_safe(self, path: Path) -> pd.DataFrame:
        """Essaie utf-8 d'abord, puis latin1 en secours (certains fichiers
        CICIDS2017, notamment Wednesday/Thursday-Morning, ne sont pas en UTF-8)."""
        try:
            return pd.read_csv(path, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            print(f"   -> encodage utf-8 echoue pour {path.name}, essai en latin1")
            return pd.read_csv(path, low_memory=False, encoding="latin1")

    def show_info(self):
        print(self.data.head())
        print("\nNombre de lignes :", len(self.data))
        print("\nColonnes :", len(self.data.columns))

    def stratified_sample(self, per_label: int = 5, random_state: int = 42) -> list:
        """
        Retourne une liste d'index (utilisables avec create_network_flow)
        contenant au maximum `per_label` lignes par valeur de Label,
        en excluant BENIGN.
        """
        label_col = " Label" if " Label" in self.data.columns else "Label"

        df = self.data[self.data[label_col].astype(str).str.strip() != "BENIGN"]

        sampled_frames = []
        for label, group in df.groupby(label_col):
            n = min(len(group), per_label)
            sampled_frames.append(group.sample(n=n, random_state=random_state))

        sample = pd.concat(sampled_frames)

        print(f"\nEchantillon stratifie : {len(sample)} alertes, "
            f"{sample[label_col].nunique()} types d'attaque distincts")
        print(sample[label_col].value_counts())

        return sample.index.tolist()

    def create_network_flow(self, index: int) -> NetworkFlow:
        """
        Transforme une ligne CICIDS en objet NetworkFlow
        """
        row = self.data.iloc[index]

        flow = NetworkFlow(
            flow_id=row["Flow ID"],
            source_ip=row[" Source IP"],
            destination_ip=row[" Destination IP"],
            source_port=int(row[" Source Port"]),
            destination_port=int(row[" Destination Port"]),
            protocol=int(row[" Protocol"]),
            timestamp=row[" Timestamp"],
            flow_duration=int(row[" Flow Duration"]),
            total_fwd_packets=int(row[" Total Fwd Packets"]),
            total_backward_packets=int(row[" Total Backward Packets"]),
            flow_bytes_per_second=float(row["Flow Bytes/s"]),
            flow_packets_per_second=float(row[" Flow Packets/s"]),
            label=row[" Label"],
            raw_features=row.to_dict()
        )

        return flow