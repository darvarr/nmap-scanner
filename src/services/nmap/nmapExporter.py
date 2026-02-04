from nmap import PortScanner
import csv


class NmapExporter:

    def export_results(self, nmap_result: PortScanner, output_path: str, output_format: str = "text"):
        if output_format == "csv":
            self.__export_csv(nmap_result, output_path)
        else:
            self.__export_text(nmap_result, output_path)

    @staticmethod
    def __export_csv(nmap_result: PortScanner, output_path: str):
        csv_results = nmap_result.csv()
        with open(output_path, mode="w+", newline="", encoding="utf-8") as file:
            writer = csv.writer(file, delimiter=";")
            for line in csv_results.strip().split("\n"):
                writer.writerow(line.split(";"))

    @staticmethod
    def __export_text(nmap_result: PortScanner, output_path: str):
        text_results = nmap_result.get_nmap_last_output().decode("utf-8")
        with open(output_path, "w") as file:
            file.write(text_results)
