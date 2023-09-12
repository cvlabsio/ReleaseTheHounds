#!/usr/bin/env python3
import hmac
import hashlib
import base64
import json
import requests, urllib3
import urllib.parse
import datetime, time

from typing import Optional
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PRINT_PRINCIPALS   = False
PRINT_ATTACK_PATH_TIMELINE_DATA = False
PRINT_POSTURE_DATA = False

DATA_START      = "1970-01-01T00:00:00.000Z"
DATA_END        = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' # Now
RELATIONSHIPS   = ["Contains","GPLink","HasSIDHistory","MemberOf","TrustedBy","AdminTo","AllowedToAct","AllowedToDelegate","CanPSRemote","CanRDP","ExecuteDCOM","SQLAdmin","DCSync","DumpSMSAPassword","HasSession","ReadGMSAPassword","ReadLAPSPassword","SyncLAPSPassword","AddMember","AddSelf","AllExtendedRights","ForceChangePassword","GenericAll","Owns","GenericWrite","WriteDacl","WriteOwner","AddAllowedToAct","AddKeyCredentialLink","WriteAccountRestrictions","WriteSPN","AZAppAdmin","AZCloudAppAdmin","AZContains","AZGlobalAdmin","AZHasRole","AZManagedIdentity","AZMemberOf","AZNodeResourceGroup","AZPrivilegedAuthAdmin","AZPrivilegedRoleAdmin","AZRunsAs","AZAddMembers","AZAddOwner","AZAddSecret","AZExecuteCommand","AZGrant","AZGrantSelf","AZOwns","AZResetPassword","AZMGAddMember","AZMGAddOwner","AZMGAddSecret","AZMGGrantAppRoles","AZMGGrantAppRoles","AZGetCertificates","AZGetKeys","AZGetSecrets","AZAvereContributor","AZKeyVaultContributor","AZOwner","AZContributor","AZUserAccessAdministrator","AZVMAdminLogin","AZVMContributor","AZAKSContributor","AZAutomationContributor","AZLogicAppContributor","AZWebsiteContributor"]

# ANSI escape codes for colors
BLACK   = '\033[30m'
RED     = '\033[31m'
GREEN   = '\033[32m'
YELLOW  = '\033[33m'
BLUE    = '\033[34m'
MAGENTA = '\033[35m'
CYAN    = '\033[36m'
WHITE   = '\033[37m'
BOLD    = '\033[1m'  # Text style for bold
RESET   = '\033[0m'  # Reset the color to the default


class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key


class APIVersion(object):
    def __init__(self, api_version: str, server_version: str) -> None:
        self.api_version = api_version
        self.server_version = server_version


class Domain(object):
    def __init__(self, name: str, id: str, collected: bool, domain_type: str, impact_value: int) -> None:
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected
        self.impact_value = impact_value


class AttackPath(object):
    def __init__(self, id: str, title: str, domain: Domain) -> None:
        self.id = id
        self.title = title
        self.domain_id = domain.id
        self.domain_name = domain.name.strip()

    def __lt__(self, other):
        return self.exposure < other.exposure


class Client(object):
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials


    def _format_url(self, uri: str) -> str:
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]

        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"


#    def _request(self, method: str, uri: str, body: Optional[bytes] = None, checkTls: bool = True) -> requests.Response:   # PROD enforces TLS cert checking
    def _request(self, method: str, uri: str, body: Optional[bytes] = None, checkTls: bool = False) -> requests.Response:    # DEV does not verify TLS
        # Digester is initialized with HMAC-SHA-256 using the token key as the HMAC digest key.
        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)

        # OperationKey is the first HMAC digest link in the signature chain. This prevents replay attacks that seek to
        # modify the request method or URI. It is composed of concatenating the request method and the request URI with
        # no delimiter and computing the HMAC digest using the token key as the digest secret.
        #
        # Example: GET /api/v1/test/resource HTTP/1.1
        # Signature Component: GET/api/v1/test/resource
        digester.update(f"{method}{uri}".encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey is the next HMAC digest link in the signature chain. This encodes the RFC3339 formatted datetime
        # value as part of the signature to the hour to prevent replay attacks that are older than max two hours. This
        # value is added to the signature chain by cutting off all values from the RFC3339 formatted datetime from the
        # hours value forward:
        #
        # Example: 2020-12-01T23:59:60Z
        # Signature Component: 2020-12-01T23
        datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing is the last HMAC digest link in the signature chain. This encodes the request body as part of
        # the signature to prevent replay attacks that seek to modify the payload of a signed request. In the case
        # where there is no body content the HMAC digest is computed anyway, simply with no values written to the
        # digester.
        if body is not None:
            digester.update(body)

        # Perform the request with the signed and expected headers
        return requests.request(
            method=method,
            url=self._format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
                "Authorization": f"bhesignature {self._credentials.token_id}",
                "RequestDate": datetime_formatted,
                "Signature": base64.b64encode(digester.digest()),
                "Content-Type": "application/json",
            },
            data=body,
            verify=checkTls    # Used for testing purposes
        )


    def get_version(self) -> APIVersion:
        response = self._request("GET", "/api/version")
        payload = response.json()
        
        return APIVersion(api_version=payload["data"]["API"]["current_version"], server_version=payload["data"]["server_version"])


    def get_domains(self) -> list[Domain]:
        response = self._request('GET', '/api/v2/available-domains')
        payload = response.json()['data']

        domains = list()
        for domain in payload:
            domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"], domain["impactValue"]))

        return domains
        
        
    def start_job(self) -> int:
        '''
        Start a new job for to upload
        '''
        print('[*] Starting a new job ... ', end='')
        r = self._request('POST', '/api/v2/file-upload/start')
        job_id = r.json()['data']['id']
        print(f'Successfully started Job {job_id}!')
        return job_id
        
        
    def stop_job(self, job_id) -> bool:
        '''
        Stop a job you started
        '''
        print(f'[*] Stopping Job {job_id} ... ', end='')
        r = self._request('POST', f'/api/v2/file-upload/{job_id}/end')
        if r.status_code == 200:
            print(f'Job {job_id} stopped successfully.')
            return True
        else:
            print(f' !!! Could not stop Job {job_id} !!!')
            return False
            
            
    def get_job_status(self, job_id) -> dict:
        '''
        Checks status of provided job. Returns status code for job ID:
          - 1: Job is "Running" (uploading)
          - 2: Job is "Complete" (good!)
          - 4: Issue with timeout
          - 6: Job is still ingesting data...wait a bit :)
        '''
        r = self._request('GET', f'/api/v2/file-upload?skip=0&limit=0&sort_by=-id')
        all_job_info = r.json()['data']     # List of jobs as dictionaries
        for job in all_job_info:
            if job.get("id") == job_id:
                return job 
        return {}
        
    
    def wait_for_job_to_finish(self, job_id):
        '''
        Calls get_job_status and waits for a valid response
        '''
        print(f'[*] Waiting for Job {job_id} to finish ingesting...NOM NOM NOM')
        job_status_code = 0     # Initialize status code with 0
        while job_status_code == 0 or job_status_code == 1 or job_status_code == 6:
            # While in initial check, "Running", or "Ingesting": Sleep a few secs, then check again
            job_status = self.get_job_status(job_id)
            job_status_code = job_status['status']
            time.sleep(3)
        print(f'[*] Job {job_id} now has status code: {job_status_code} {job_status["status_message"]}')
        return
        
    
    def object_search(self, searchobj) -> dict:
        '''
        Searches for an object and returns a blob including the SID, objtype, UPN, and DN
        '''
        encoded_query = urllib.parse.quote(searchobj)
        #print(f'[*] Searching for {searchobj}, URL-encoded: "{encoded_query}"')    # DEBUG
        r = self._request('GET', f'/api/v2/search?q={encoded_query}')
        if r.status_code == 200:
            # Request was successful. Returns 200 if there's a result or not
            return r.json()
        else:
            print(f'[!] Request failed with a {r.status_code}! Behavior will be unexpected...')
            return


    def query_attack_path(self, src_sid, dst_sid, exclude_relationships) -> dict:
        '''
        Query the shortest path from source to destination
        '''
        # Default queries every possible edge
        exclude_list = exclude_relationships.split(',')
        exclude_list_lower = [r.lower() for r in exclude_list]
        relationships_included = [r for r in RELATIONSHIPS if r.lower() not in exclude_list_lower]
        query = f'start_node={src_sid}&end_node={dst_sid}&relationship_kinds=in:'
        for i,r in enumerate(relationships_included):   # Formulate list of all relationships
            query += r
            query += ',' if i < len(relationships_included) - 1 else ''
        #print(query)       # DEBUG
        r = self._request('GET', f'/api/v2/graphs/shortest-path?{query}')
        if r.status_code == 200:
            # Request was successful. Returns 200 if there's a result or not
            return r.json()
        else:
            print(f'[!] Request failed with a {r.status_code}! Behavior will be unexpected...')
            return r.json()


    def chunk_and_submit_data(self, data_to_chunk, num_objs_in_chunk=250, num_chunks_per_job=50):
        '''
        Takes a large JSON blob loaded from load_file:
            - Chunks it into manageable pieces of {num_objs_in_chunk} chunks
            - Submits each chunk to a job {job_id} of chunk size {num_chunks_per_job}
            - Checks status of previous job. If completed, start next/new job.
        '''
        
        # Extract metadata from the JSON data
        meta_data = data_to_chunk.get("meta", {})
        methods = meta_data.get("methods", 0)
        data_type = meta_data.get("type", "")
        print(f'[*] Uploading data for {data_type}')
        version = meta_data.get("version", "")
        
        # Extract the "data" array from the large JSON data
        data_list = data_to_chunk.get("data", [])
        # Split the "data" array into chunks
        data_chunks = [data_list[i:i + num_objs_in_chunk] for i in range(0, len(data_list), num_objs_in_chunk)]

        # Iterate through the data chunks and send each chunk as a separate POST request
        chunk_count = 0 
        for index, chunk in enumerate(data_chunks, start=1):
            # If total chunks is cleanly divisible by num_chunks_per_job, then submit new job and stop previous
            if chunk_count % num_chunks_per_job:
                need_new_job = False
            else:
                need_new_job = True
                if "job_id" in locals() and chunk_count != 0:
                    # If there's already a job submitted and we need a new job, stop job & sleep until done processing
                    self.stop_job(job_id) 
                    # Now, wait until that job is done processing for the next job
                    self.wait_for_job_to_finish(job_id)                
                else:
                    print('[*] Starting initial job')
                job_id = self.start_job()
                #print(f'[+] Job ID {job_id} started')
            
            # Prepare the JSON data for the chunk
            chunk_data = {
                "data": chunk,
                "meta": {
                    "methods": methods,
                    "type": data_type,
                    "count": len(chunk),  # Update the "count" for this chunk
                    "version": version
                }
            }
            
            # Convert the chunk data to a JSON string
            bhchunk_data_string = json.dumps(chunk_data)

            # Encode the JSON data string to bytes
            bhchunk_data_bytes = bhchunk_data_string.encode('utf-8')
            
            # Upload now
            r = self._request('POST', f'/api/v2/file-upload/{job_id}', body=bhchunk_data_bytes)
            if r.status_code != 202:
                print(f'[-] Issue uploading data with status code: {r.status_code}')
            chunk_count += 1

        # Ended chunky upload. Now we stop the last job and wrap it up.
        self.stop_job(job_id) 
        self.wait_for_job_to_finish(job_id)   
        print(f'[+] Uploaded {chunk_count} chunks of {num_objs_in_chunk} objects each to API.')
        return

    
    def get_attack_paths(self, source, destination, exclude_relationships):
        '''
        Takes a source node and identifies attack paths to destination node.
            - Determine if you need to load source from files
            - For each source
                - Resolve the SID with "search" API for source/dest
                - Query for attack paths & return results
        '''
        print(f'[*] Getting paths to {destination}')
        # Find SID for source
        search_results_src = self.object_search(source)
        if len(search_results_src['data']) == 0:
            print(f'[-] Searching for {source} failed - No results! Try again.')
            exit()
        elif len(search_results_src['data']) > 1:
            print(f'[*] Searching for {source} yielded more than 1 result! Using first: {search_results_src["data"][0]["name"]}')
            print(f'    All matches:')
            for r in search_results_src['data']:
                print(f'        Name:                 {r["name"]}')
                print(f'        Distinguished Name:   {r["distinguishedname"]}')
        src_sid = search_results_src["data"][0]["objectid"]
        print(f'[*] Found source {search_results_src["data"][0]["type"]} "{search_results_src["data"][0]["name"]}" with SID "{src_sid}" for: "{source}"')

        search_results_dst = self.object_search(destination)
        if len(search_results_dst['data']) == 0:
            print(f'[-] Searching for {destination} failed - No results! Try again.')
            exit()
        elif len(search_results_dst['data']) > 1:
            print(f'[*] Search yielded more than 1 result! Using first: {search_results_dst["data"][0]["name"]}')
            print(f'    All matches:')
            for r in search_results_dst['data']:
                print(f'        Name:                 {r["name"]}')
                print(f'        Distinguished Name:   {r["distinguishedname"]}')
        dst_sid = search_results_dst["data"][0]["objectid"]
        print(f'[*] Found destination {search_results_dst["data"][0]["type"]} "{search_results_dst["data"][0]["name"]}" with SID "{dst_sid}" for: "{destination}"')

        ## Query the shortest path!!
        print(f'{BOLD}{RED}[*] <-=-=-=-=-=-=-=-=-=-=-=- QUERYING ATTACK PATHS -=-==-=-=-=-=-=--=-=-=->{RESET}')
        shortest_path_results = self.query_attack_path(src_sid, dst_sid, exclude_relationships)
        try:
            path_data = shortest_path_results['data']
            print(f'[+] Attack path found for {path_data["nodes"][path_data["edges"][0]["source"]]["label"]}!')
            print(f'{BOLD}{MAGENTA}[{path_data["nodes"][path_data["edges"][0]["source"]]["label"]}]{RESET} ', end='')
            for edge in path_data['edges']:
                print(f'{BOLD}{CYAN}<{edge["kind"]}>{RESET} ', end='')
                print(f'{MAGENTA}[{path_data["nodes"][edge["target"]]["label"]}]{RESET} ', end='')
            print('')   # Get fresh line to clear it
        except:
            print(f'[-] No attack paths found!')

        print('')
        return

