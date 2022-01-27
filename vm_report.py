"""
vm_report.py: Script to get CSV report of certain VM-level metrics
from the v1 API
"""
import requests
import json
import datetime
import urllib3
import sys
import logging
import argparse
import getpass
import re
import math
from base64 import b64encode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
current_time = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


class RequestParameters:
    """
    Class to hold the parameters of our Request
    """

    def __init__(self, uri, username, password):
        self.uri = uri
        self.username = username
        self.password = password

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"uri={self.uri},"
            f"username={self.username},"
            f"password={self.password},"
        )


class RequestResponse:
    """
    Class to hold the response from our Request
    """

    def __init__(self):
        self.code = 0
        self.message = ""
        self.json = ""
        self.details = ""

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"code={self.code},"
            f"message={self.message},"
            f"json={self.json},"
            f"details={self.details})"
        )


class RESTClient:
    """
    the RESTClient class carries out the actual API request
    by 'packaging' these functions into a dedicated class
    """

    def __init__(self, parameters: RequestParameters):
        self.params = parameters

    def request(self):
        """
        this is the main method that carries out the request
        basic exception handling is managed here, as well as
        returning the response (success or fail), as an instance
        of our RequestResponse
        """
        response = RequestResponse()
        """
        setup the HTTP Basic Authorization header based on the
        supplied username and password
        """
        username = self.params.username
        password = self.params.password
        encoded_credentials = b64encode(
            bytes(f"{username}:{password}", encoding="ascii")
        ).decode("ascii")
        auth_header = f"Basic {encoded_credentials}"

        # Create the headers with the previous creds
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{auth_header}",
            "cache-control": "no-cache",
        }
        try:
            api_request = requests.get(
                self.params.uri, headers=headers, timeout=30, verify=False
            )
            # if no exceptions occur here, we can process the response
            response.code = api_request.status_code
            response.message = "Request submitted successfully."
            response.json = api_request.json()
            response.details = "N/A"
        except ValueError:
            # handle when our APIs do not return a JSON body
            response.code = api_request.status_code
            response.message = "ValueError was caught."
            response.details = "N/A"
        except requests.exceptions.ConnectTimeout:
            # timeout while connecting to the specified IP address or FQDN
            response.code = -95
            response.message = f"Connection has timed out. {username} " + f"{password}"
            response.details = "Exception: requests.exceptions.ConnectTimeout"
        except urllib3.exceptions.ConnectTimeoutError:
            # timeout while connecting to the specified IP address or FQDN
            response.code = -96
            response.message = "Connection has timed out."
            response.details = "urllib3.exceptions.ConnectTimeoutError"
        except requests.exceptions.MissingSchema:
            # potentially bad URL
            response.code = -97
            response.message = "Missing URL schema/bad URL."
            response.details = "N/A"
        except Exception as _e:
            # unhandled exceptions
            response.code = -99
            response.message = "An unhandled exception has occurred."
            response.details = _e

        return response


class NameFilter(logging.Filter):
    """
    Class to contextually change the log based on the VM being processed
    """

    def __init__(self, entity_name):
        self.entity_name = entity_name

    def filter(self, record):
        record.entity_name = self.entity_name
        return True

def split_list(lst, n):
    """
    Function to yield successive n-sized chunks from a list.
    Used for constructing multiple URLs depending on
    number of metrics desired
    """
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def api_request(url, pe_ip, pe_user, pe_password):
    """Create a new entity via a v3 post call, return the response"""

    # Make the API call
    parameters = RequestParameters(uri=url, username=pe_user, password=pe_password)
    rest_client = RESTClient(parameters)
    resp = rest_client.request()

    return resp


def custom_log(entity_name):
    """
    Custom log to include current entity name being processed
    """
    logger = logging.getLogger(__name__)
    logger.addFilter(NameFilter(entity_name))

    if not logger.hasHandlers():
        logname = f"{entity_name}-log-{current_time}.log"
        filelog = logging.FileHandler(filename=logname)
        formatter = logging.Formatter(
            "%(levelname).1s %(asctime)s [%(entity_name)s] %(message)s"
        )
        filelog.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        print(f"Logging to {logname}")
        logger.addHandler(filelog)
    return logger


def get_cluster_name(pe_ip, pe_user, pe_password):
    """
    Given a Prism Element IP, return the name of the cluster
    """
    cluster_url = f"https://{pe_ip}:9440/PrismGateway/services/rest/v1/clusters"
    resp = api_request(cluster_url, pe_ip, pe_user, pe_password)

    if resp.code >= 500:
        print("An HTTP server error has occurred (" f"{api_request.status_code})")
    else:
        if resp.code == 401:
            print(
                "An authentication error occurred while connecting to "
                f"{pe_ip}. Please check your credentials, "
                "then try again."
            )
            sys.exit(1)
        if resp.code >= 401:
            print(
                "An HTTP client error has occurred (" f"{api_request.status_code})"
            )
            sys.exit(1)
        else:
            print("Connected and authenticated successfully.")

            cluster_info = resp.json

            for i in cluster_info["entities"]:
                cluster_name = i["name"]

            return cluster_name


def main(pe_ip, pe_user, pe_password, report_name, duration):
    """
    Main function for the script
    Queries the required APIs, does the required calculations, and constructs the report
    """
    log_delimiter = "==========================================="
    cluster_name = get_cluster_name(pe_ip, pe_user, pe_password)

    if not report_name:
        if duration:
            filename = f"{cluster_name}-vm-report-last{duration}days-{current_time}.csv"
        else:
            filename = f"{cluster_name}-vm-report-{current_time}.csv"
    else:
        filename = report_name
    report = open(filename, "w")

    # URL for Stats of All VM Stats
    url = f"https://{pe_ip}:9440/PrismGateway/services/rest/v1/vms"

    # remove any whitespace from cluster_name as it will be used in the log filename
    cluster_name = re.sub(r"\s+", "-", cluster_name)
    logger = custom_log(cluster_name)
    logger.info(f"Report being written to {filename}")
    logger.info(f"{url}")
    logger.info(log_delimiter)

    resp = api_request(url, pe_ip, pe_user, pe_password)
    results = resp.json
    try:
        total_vms = results.get("metadata", {}).get("grandTotalEntities")
    except Exception as e:
        logger.error(f"Error when parsing metadata: {e}")
        sys.exit(1)
    logger.info(f"Total VMs: {total_vms}")

    if duration:
        logger.info(f"Getting VM metrics for last {duration} days")

    # setup a variable that can be used to store our JSON configuration
    config_json = {}

    # grab and decode the category details from the included JSON file
    with open("./config.json", "r") as config:
        config_json = json.loads(config.read())

    # these dicts map the desired attributes and metrics
    # with the display names that will be used in the report
    attributes = config_json["config"]["attributes"]
    metrics = config_json["config"]["metrics"]

    # Headings
    for attr in attributes.values():
        report.write(f"{attr},")
    for metric in metrics.values():
        report.write(f"{metric} (Max),")
        report.write(f"{metric} (Average),")

    report.write("\n")

    # Content
    for vm in results["entities"]:
        vm_name = vm["vmName"]
        logger = custom_log(vm_name)
        vm_uuid = vm["uuid"]

        for attr, display_name in attributes.items():
            if attr == "clusterUuid":
                report.write(f"{cluster_name}" + ",")
            elif "Bytes" in attr:
                # 1073741824 bytes = 1 GiB
                if vm[f"{attr}"]:
                    value_in_gib = int(vm[f"{attr}"] / 1073741824)
                else:
                    value_in_gib = 0
                logger.info(f"{display_name}: {value_in_gib} GiB")
                report.write(f"{value_in_gib} GiB,")
            else:
                attribute_value = vm[f"{attr}"]
                logger.info(f"{display_name}: {attribute_value}")
                report.write(str(attribute_value) + ",")

        logger.info(log_delimiter)

        # First we will construct the URL(s)
        # We have to do multiple calls because only 5 metrics are supported at a time
        metrics = []
        for vm_metric in metrics.items():
            metrics.append(vm_metric[0])

        # first split the metric list into chunks of 5
        # e.g. for 6 metrics we'll have two lists
        # [
        #   ['hypervisor_cpu_usage_ppm', 'guest.memory_usage_bytes', 'memory_usage_ppm', 
        #        'controller_user_bytes', 'hypervisor_num_received_bytes'],
        #   ['hypervisor_num_transmitted_bytes']
        # ]
        url_param_full_list = list(split_list(metrics, 5))

        for params in url_param_full_list:
            # turn list into a string
            str_params = ','.join(map(str, params))
            
            print(str_params)

            if duration == 0:
                metric_url = f"{url}/{vm_uuid}/stats/?metrics={str_params}"
            else:
                startTimeInUsecs = int(
                    (
                        datetime.datetime.now() - datetime.timedelta(days=int(duration))
                    ).timestamp()
                    * 1000000
                )
                metric_url = f"{url}/{vm_uuid}/stats/?metrics={str_params}&" + \
                    f"startTimeInUsecs={startTimeInUsecs}"

            metric_resp = api_request(metric_url, pe_ip, pe_user, pe_password)
            metric_results = metric_resp.json

            logger.info(f"URL: {metric_url}")
            logger.info(log_delimiter)
            # left off here-ish 12/20/21
            if metric_results.get("statsSpecificResponses"):
                # for one metric, there's only one element
                for i in metric_results["statsSpecificResponses"]:
                    message = i["message"]
                    num_of_values = len(i["values"])
                    if num_of_values > 0:
                        max_value = int(max(i["values"]))
                        average = int(float(sum(i["values"]) / num_of_values))

                        logger.info(f"Length of value list: {num_of_values}")
                        logger.info(f"Max Value in value list: {max_value}")
                        logger.info(f"Average Value in value list: {average}")

                        if "controller_user_bytes" in vm_metric:
                            # For Disk Usage report as a %, so need to divide
                            # by total capacity
                            total_disk_cap = vm.get("diskCapacityInBytes")
                            if total_disk_cap:
                                # print("total_disk_cap: " + str(total_disk_cap))
                                max_value = float(
                                    "{:.2f}".format((max_value / total_disk_cap) * 100)
                                )
                                average = float(
                                    "{:.2f}".format((average / total_disk_cap) * 100)
                                )
                            else:
                                max_value = 0
                                average = 0
                        elif "ppm" in vm_metric:
                            # reported in parts per million, divide by 1e6 and
                            # multiply by 100 to get %
                            max_value = float(
                                "{:.2f}".format((max_value / 1000000) * 100)
                            )
                            average = float("{:.2f}".format((average / 1000000) * 100))
                        elif "memory_usage_bytes" in vm_metric:
                            # convert bytes to GiB - divide by 1073741824
                            max_value = float("{:.2f}".format(max_value / 1073741824))
                            average = float("{:.2f}".format(average / 1073741824))
                        elif "hypervisor_num" in vm_metric:
                            # convert bytes to kilobits - divide by 125
                            max_value = float("{:.2f}".format(max_value / 125))
                            average = float("{:.2f}".format(average / 125))
                        logger.info(f"Max Value after conversion: {max_value}")
                        logger.info(f"Average Value after conversion: {average}")
                        logger.info(log_delimiter)
                        report.write(f"{max_value},")
                        report.write(f"{average},")
                    else:
                        # Log a warning if no values were returned
                        logger.warning(message)
                        logger.info(log_delimiter)
                        max_value = 0
                        average = 0
                        report.write("0,0,")
            else:
                logger.error(f"Error fetching stat details for {vm_name}")
        report.write("\n")

    report.close()

    print(f"Report written to {filename}")
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pe_ip", help="Prism Element IP address")
    parser.add_argument("-u", "--username", help="Prism Element username")
    parser.add_argument("-p", "--password", help="Prism Element password")
    parser.add_argument("-d", "--duration", help="Number of days to report on")
    parser.add_argument("-f", "--filename", help="Desired report filename")
    # parser.add_argument("-d", "--debug", help="Enable/disable debug mode")

    args = parser.parse_args()

    pe_user = (
        args.username
        if args.username
        else input("Please enter your Prism Element username: ")
    )
    pe_password = args.password if args.password else getpass.getpass()

    pe_ip = args.pe_ip

    # optional arguments
    report_name = args.filename

    duration = args.duration

    if duration:
        try:
            duration = int(duration)
        except Exception:
            duration = input("Please enter a valid duration in days: ")
            if not duration:
                duration = 30
                print("No duration specified, getting metrics for last 30 days")
    else:
        duration = 30

    # self.debug = True if args.debug == "enable" else False
    main(pe_ip, pe_user, pe_password, report_name, duration)
