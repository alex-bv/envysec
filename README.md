# secEnvyronment

## Content table:
* Introducing.
* Tutorial.
* API reference.
* Developer documentation.


## Introducing:

This software is used to simplify ClamAV usage and automatize detect verification using Metadefender service.

Scope:
* Reduce number of false-positive detection;
* Simplify user interface;
* Provide less overloaded detection reports.

Usage cases:
* Manual or scheduled virus-scanning;
* Simple IP-abuse scanning.

Limitations:
* Number of Metadefender scans are limited by one's API key. Free API key is limited to 10 scans per day.


## Tutorial:

Installation guide is described in **INSTALL.md** file.
Application does not require any special workspace preparations.

To get help use:
```
python3 envy_sec.py --help
python3 envy_sec.py -h
```

To perform file scan:
```
python3 envy_sec.py -S path/to/file/to/be/scann.ed
python envy_sec.py --scan-file C:\PathTo\File\ToBeScann.ed
```

To perform IP scan:
```
python3 envy_sec.py --scan-ip 8.8.8.8
python3 envy_sec.py -I 8.8.8.0\24
```

To perform ClamAV signatures update:
```
python3 envy_sec.py --update
python3 envy_sec.py -U
```

To send multiple arguments use space:
```
python3 envy_sec.py -I 8.8.8.8 9.9.9.9
```

Commands also might be combined:
```
python3 envy_sec.py --update -I 8.8.8.8 9.9.9.9 -F ./eicar.virus /some/another/file
```

Command execution priority:
1. Update;
2. Scan IP;
3. Scan file;


## API reference:

Source code reference might be found in docs/API reference dir.
(./API-reference/index.html)


## Developer documentation:

This section describes how exactly does secEnvyronment works (or does not). 

Briefly, how does it work:
- User invokeы secEnvyronment scan,
- secEnvyronment open ClamAV subprocess, 
- and put all ClamAV output in queue,
- in parallel, thread (work_thread) checks for new lines in queue,
- and if thread finds something, it sends it to Metadefender,
- then prints out approved or denied result.

<pre>
                Approve or deny ClamAV detection,
                         output results.
             ________________________________________
            |                                        |
            |                                        |
  (1) secEnvyronment     work_thread ----------> Metadefender
            |                 |        call with
 subprocess |                 |      received from
    popen() |                 |        queue args
            |     put in      |      
         ClamAV ----------> queue     
 
             The main principal work scheme (1 - begin)
</pre>

### Metadefender Errors:

1. HTTP code is HTTP status code, used to control HTTP session status 
   (like if server work or not, connection refused and etc.);
2. Response code placed in response JSON, used to control Metadefender session status
   (like data validity, API key limits and etc.);
3. Description is a response code explanation;
   (like why this happened);

Metadefender code | Category | HTTP code
----------------- | -------- | ----------
 | **Generic** | 
400000 | Generic error | 400
400001 | The caching strategy is not recognized | 400
400002 | The limit strategy is not supported | 400
400003 | The limit type is not supported | 400
400004 | The query parameters are not valid | 400
 | **Payload Validation** | 
400020 | Header is not valid | 400
400021 | Body parsing failed | 400
400022 | Payload validation has failed | 400
400023 | Headers are not correct | 400
400024 | Headers are missing | 400
400025 | Payload is missing or empty | 400
400026 | Hash in the URL doesn't match the hash value in the body | 400
400027 | Offset should be a positive integer | 400
400028 | "Limit should be a positive integer less than 10.000" | 400
 | **Routing Errors** | 
400040 | The requested path is not valid | 400
400041 | The version is required | 400
400042 | The version does not exist | 400
400043 | The requested path does not exist | 400
400044 | Method does not exist | 400
400045 | The route was not properly set up | 400
400046 | The requested route does not exist | 400
400047 | This route is available only on development environments | 400
 | **Hash Errors** |   
400060 | The `hash` field in the body is required | 400
400061 | The `hash` field is not an array | 400
400062 | The `hash` field is empty | 400
400063 | Exceeded maximum allowed | 400
400064 | The hash value is not valid | 400
400065 | The header `include_scan_details` has to be either 0 or 1 | 400
400066 | The header `file_metadata` has to be either 0 or 1 | 400
400067 | Hash update failed | 400
 | **Top Hash Errors** | 
400080 | The amount must be lower than 10.000 | 400
400081 | Type must be one of `clean` / `infected` | 400
400082 | Period must be one of `day` / `week` / `month` | 400
400083 | Threshold must be one of 1, 2, 3, 4, 5, 6  | 400
 |**appinfo** | 
400100 | The fields `os_info.device_identity` are required | 400
 | **Top Detection** | 
400120 | The header `x-exclude-empty-file-id` has to be either 0 or 1 | 400
400121 | The header `x-exclude-data` has to be either 0 or 1 | 400
400122 | The header `x-threshold` must be one of 3, 4, 5, 6  | 400
400123 | Packages should be one of m1, m4, m8, m12, m16, m20, m30 | 400
400124 | Number of hashes must be one of 10, 100, 1.000, 10.000 | 400
 | **Upload Errors** | 
400140 | The file upload has failed | 400
400141 | The header `x-force-scan` has to be either 0 or 1 | 400
400142 | The header `x-sample-sharing` has to be either 0 or 1 | 400
400143 | Private scanning is not enabled for the provided API key | 400
400144 | Exceeded maximum file size allowed; maximum allowed is 200MB | 400
400145 | Request body is empty; please send a binary file | 400
400146 | Provided download URL is not valid or inaccessible | 400
400147 | Rescan failed. Requested file is missing from our servers. | 400
400148 | Requested file is a private one and cannot be rescanned | 400
400149 | Could not update the rescan count | 400
400150 | The `file_ids` field array in body is required | 400
400151 | The `file_ids` field is not an array | 400
400152 | The `file_ids` field is empty | 400
400153 | Exceeded maximum allowed | 400
400154 | Exceeded maximum allowed files in archive | 400
 | **API Key Info** | 
400160 | The API key you are trying to add already exists | 400
400161 | The API key could not be removed | 400
400162 | The API key was not updated | 400
400163 | The body is invalid | 400
400164 | No valid operation type | 400
400165 | No API key specified | 400
400166 | Please provide a valid email address | 400
400167 | Please provide a valid body | 400
400168 | Please choose another nickname, as this one contains profanities | 400
 | **IP Scan** | 
400180 | Invalid format of input. Provide IPv4 or IPv6. | 400
400181 | The `ip_addresses` field in body is required | 400
400182 | The `ip_addresses` field is not an array | 400
400183 | The `ip_addresses` field is empty | 400
400184 | Exceeded maximum allowed | 400
400185 | The address is not a routable IP | 400
400186 | No response | 400
400187 | Invalid response | 400
 | **Stats** | 
400200 | The number of days requested must be a positive integer | 400
400201 | Invalid objectId | 400
400202 | Invalid date | 400
400203 | Invalid outbreak report filter | 400
 | **Status** | 
400210 | Parameter type must be one of `hashLookup` / `uploadFile` / `ipScan`         400
 | **Salesforce** | 
400250 | Salesforce connectivity error | 401
400251 | There is no record | 401
 | **Feed** | 
400260 | You are allowed to query up to 30 days in the past | 400
400261 | Invalid category. Please use: A, D, E, G, M, N, O, P, T, Z | 400
 | **Authentication** | 
401000 | Authentication has failed | 401
401001 | Authentication strategy is invalid | 401
401002 | Authentication strategy is not implemented | 401
401003 | Authorization strategy is not supported for this endpoint | 401
401004 | Authentication token has expired | 401
401005 | Authentication token is invalid | 401
401006 | Invalid API key | 401
 | **Forbidden** | 
403000 | Access forbidden | 403
403001 | Requested resource doesn't match your API key | 403
403002 | Your IP is blocked because of abuse | 403
403003 | Insufficient Privileges | 403
 | **Not Found** | 
404000 | Endpoint was not found | 404
404001 | Entity was not found | 404
404002 | There are no entries found | 404
404003 | The hash was not found | 404
404004 | The data_id was not found | 404
404005 | The hash information was not found | 404
404006 | There is no data for the selected date | 404
404007 | Requested file ID does not exist in our records | 404
404008 | The API key was not found | 404
 | **Payload Acceptance** | 
406000 | Content-Type header and payload has to be JSON | 406
406001 | Payload empty | 406
 | **Request Timeout** | 
408000 | Request timeout. It has reached the 60 seconds limit. | 408
 | **Rate Limiting** | 
429000 | API key limit exceeded; retry after the limit is reset | 429
429001 | Your request has been throttled; maximum 10 requests per minute per user | 429
429002 | Too many connections; try again later | 429
 | **Service Unavailable** | 
503000 | External service is not reachable | 503
503001 | External service is not reachable | 503
