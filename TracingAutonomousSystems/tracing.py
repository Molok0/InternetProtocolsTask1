import subprocess
from ipwhois import IPWhois
import ipwhois.exceptions
import re


class TracingAutonomousSystems:

    def __init__(self, domen) -> None:
        self.domen = domen

    def __get_table_tracert(self):
        return subprocess.check_output(["tracert", self.domen], encoding="cp866")

    def __parse_table_tracert(self, table):
        reg = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ip = re.findall(reg, table)
        if ip:
            return list(set(ip))
        else:
            return None

    def __search_inf_of_ip(self, ip_list):
        ip_inf = []
        for ip in ip_list:
            try:
                tmp_dict = dict()
                res = IPWhois(ip).lookup_rdap()
                tmp_dict['ip'] = res['query']
                tmp_dict['asn'] = res['asn']
                tmp_dict['asn_country_code'] = res['asn_country_code']
                tmp_dict['provider'] = res['network']['name']
                ip_inf.append(tmp_dict)
            except ipwhois.exceptions.IPDefinedError as e:
                continue
        return ip_inf

    def __print_table(self, ip_inf):
        print("№\t\tIP\t\t\tAS\t\tCOUNTRY\t\tPROVIDER\n")
        j = 1
        for i in ip_inf:
            print(
                str(j) + '\t\t' + i['ip'] + '\t\t' + i['asn'] + '\t\t' + i['asn_country_code'] + '\t\t' + i['provider'])
            j += 1

    def run(self):
        table = self.__get_table_tracert()
        ip_list = self.__parse_table_tracert(table)
        ip_inf = self.__search_inf_of_ip(ip_list)
        self.__print_table(ip_inf)
