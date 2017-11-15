# VxCortex
*VxCortex* is the name given to the project that integrates [Cortex](https://github.com/CERT-BDF/Cortex), an open-source analysis engine of cybersecurity observables written in Scala, with the RESTful Application Programming Interface (API) of [Falcon Sandbox](https://www.vxstream-sandbox.com/), an online sandbox for malware analysis belonging to Payload Security. The project relates to **one Cortex analyzer** written in Python 3.5 that integrates with the API of VxStream Sandbox. The structure of the VxCortex analyzer is valid with the [Cortex development instructions](https://github.com/CERT-BDF/CortexDocs/blob/master/api/how-to-create-an-analyzer.md) and is as follows:

* `VxStream/requirements.txt`: list of Python dependencies that the analyzer uses, depicting [`python-magic`](https://github.com/ahupp/python-magic) for determining file types, [`requests`](https://github.com/requests/requests) for HTTP interaction, and [`cortexutils`](https://github.com/CERT-BDF/Cortex-Analyzers/tree/master/contrib/cortexutils) for providing Cortex utilities;
* `VxStream/vxstream.py`: the Python entry point of the **analyzer** that integrates with the API of Falcon Sandbox;
* `VxStream/VxStream_FileAnalysis.json`: JSON configuration file that describes a file analysis service;
* `VxStream/VxStream_Search.json`: JSON configuration file that describes a search service of domain names, hash values, IP addresses and port numbers;
* `VxStream/VxStream_URLAnalysis.json`: JSON configuration file that describes a URL analysis service;
* `thehive-templates/VxStreamSandbox_FileAnalysis_1_0`: folder depicting the Angular JS templates `short.html` and `long.html` for diplaying short and long reports of file analyzes;
* `thehive-templates/VxStreamSandbox_Search_1_0`: folder depicting the Angular JS templates `short.html` and `long.html` for diplaying short and long reports of domain names, hash values, IP addresses and port numbers analyzes;
* `thehive-templates/VxStreamSandbox_URLAnalysis_1_0`: folder depicting the Angular JS templates `short.html` and `long.html` for diplaying short and long reports of URL anlayzes.

The VxCortex analyzer was developed while considering both the usefulness and completeness of its functionality with the Falcon Sandbox API in relation to the Cortex engine. These considerations are realized in the analyzer as features of analysis of malware and URLs and of retrieval of reports and data that pertain to network or file observales, which ultimately constitute the purpose of analyzers as set by Cortex.

Cortex is licensed under GNU AGPLv3 and its source code is available at its [main GitHub repository](https://github.com/CERT-BDF/Cortex). Analyzers developed for Cortex are also licensed under GNU AGPLv3 and are available at a [second GitHub repository](https://github.com/CERT-BDF/cortex-analyzers/). Cortex is documented at a [third GitHub repository](https://github.com/CERT-BDF/CortexDocs) and a work-in-progress [Read the Docs](https://cert-bund-cortex-analyzers.readthedocs.io/en/latest/index.html) page.

The `VxStream/vxstream.py` file is described in detail in the next section. The sections that follow describe `vxstream.py` and list all the API resources used by the module. The next to last section overviews the usage of the module, while the very last one lists resources consulted throughout development.

# `VxStream/vxstream.py`
Cortex analyzers can be written in any programming language supported by Linux as long as the resulting file is an executable and is properly configured to run with the engine. Cortex provides a Python package called [`cortexutils`](https://github.com/CERT-BDF/Cortex-Analyzers/tree/master/contrib/cortexutils) that is available to install through `pip` and which can be used to facilitate development of Python analyzers. The facilitator comes in the form of subclassing `Analyzer` and overriding a few specific methods. `VxStream` is the name of the subclass given to the analyzer. The next subsections compartmentalize the description of the analyzer in terms of methods, variables and general workflow of its execution.

## Methods
The **methods** of the analyzer can be described as follows, in the same order as they appear in the source code:
* `__init__`: retrieves configuration settings and instantiates variables with their values;
* `run`: defines the workflow of an analysis for each file, URL and observable;
* `mime_type`: determines the MIME type of a file and maps to an analysis environment;
* `environment`: retrieves available analysis environments and checks if the one specified in the configuration is valid;
* `submit`: submits a file or URL for analysis to `/api/submit` or `/api/submiturl`, respectively;
* `heartbeat`: checks the status of an analysis on `/api/state` according to a timeout value;
* `scan`: retrieves the report of an analysis from `/api/scan` and populates `self.result`;
* `search`: retrieves the report of observables from `/api/search` and populates `self.result`;
* `summary`: generates a summary report from `self.result`;
* `artifacts`: extracts available artifacts (*i.e.*, Indicators of Compromise (IOCs)) from `self.result`; 
* `post`: wraps `query` to change the type of HTTP request to `POST`;
* `query`: conducts HTTP `GET` (default) or `POST` requests to the VxStream Sandbox API and handles predefined response errors;
* `apifmrterr`: generates an error with a predefined message template.

## Variables
The analyzer is developed with consistency in terms of nomenclature and purpose, particularly in **variables** used in different methods that have the same purpose. Some of those are described as follows:
* `data`: `dict` with parsed JSON data or `str` with binary response data from a HTTP request;
* `msg`: `str` holding an error message to be logged;
* `param`: `dict` with `requests` fields for HTTP requests with `requests.get` or `requests.post`;
* `url`: `str` with the full URL of the API resource to be queried, excluding HTTP `GET` parameters.

Another set of **instance variables** have a module-wide scope. Of note are all module configurations that are set as instance variables, as well as the following:
* `self.data_type`: `str` holding a type of the input as set by Cortex from JSON the configuration file(s);
* `self.headers`: `dict` with the HTTP header field for HTTP queries;
* `self.result`: `dict` with results of an analysis to be parsed by Cortex in the end;
* `self.service`: `str` holding the service (*i.e.*, file or URL analysis or search) chosen by the user;
* `self.sha256`: `str` holding a SHA256 hash value of the file or URL currently submitted for analysis.

## Execution Workflow
`VxStream` starts off by determining the input type that is to be processed and the API that should be queried. The **general workflow** is as follows for file or URL input types:
1. determine the MIME type of a file if and only if the input type is a file;
2. retrieve available analysis environments and check if the one specified in the configuration is valid;
2. submit a file or URL for analysis;
3. wait for an analysis to finish or timeout;
4. retrieve an analysis report and other data to enrich the results;
5. populate `self.result`;
7. build a summary report;
8. extract artifacts from the full report.

If the input type is neither a file nor a URL, then the execution workflow is as follows for observables that are domain names, hash values, IP addresses or port numbers:
1. map the query search parameter to the observable type;
2. query the API;
3. populate `self.result`
4. build a summary report;
5. extract artifacts from the full report.

# VxStream Sandbox API List
The `VxStream` analyzer consumes a selected few API resources from VxStream Sandbox to achieve its integration with Cortex and thereby fulfill its purpose of analyzing observables. The **full list** and description of API resources used by the analyzer is, in alphabetical order, the following:
* `/api/result`: used to retrieve additional data of an analysis;
* `/api/scan`: used to retrieve reports of an analysis;
* `/api/search`: used to search for data characterizing observables;
* `/api/submit`: used to submit a file for analysis;
* `/api/submiturl`: used to submit a URL for analysis;
* `/api/state`: used to retrieve status information of an analysis;
* `/system/state`: used to determine the available analysis environments.

# Usage
Developing analyzers can be made without setting up the Cortex engine at first, requiring it only to fully test the integration with one another. Pertinently, the project that Cortex is part of, which is called [TheHive](https://thehive-project.org/), provides a customized [Ubuntu 16.04 virtual machine](https://github.com/CERT-BDF/TheHiveDocs/blob/master/training-material.md) that ships with the latest stable version of the software pre-installed that is ready for use. The system login is `thehive:thehive1234` and the software are configured as services, which can be restarted as follows:
```
$ sudo service thehive restart
$ sudo service cortex restart
$ service --status-all | egrep -i "thehive|cortex"
 [ + ]  cortex
 [ + ]  thehive
```
Both TheHive and Cortex should then be available to access via web interfaces respectively on http://a.b.c.d:9000/ and  http://a.b.c.d:9999/, where a.b.c.d is the IP address of the virtual machine with bridged networking. A log file is available under `/var/log/cortex/application.log`.

Analyzers are placed under `/opt/Cortex-Analyzers/analyzers/`, with `VxStream` being on `/opt/Cortex-Analyzers/analyzers/VxStream` and with the Angular JS templates of the analyzer being on `/opt/Cortex-Analyzers/thehive-templates/`. A template package needs to be [manually imported](https://github.com/CERT-BDF/TheHiveDocs/blob/master/admin/configuration.md#6-cortex) via the administrator web interface in `Admin > Report templates > Import templates` or else each template requires an individual definition using the provided `View Template` dialog wizard. Analyzer-specific configurations like API keys are made on the global configuration file `/etc/cortex/application.conf` under the `config {}` object. The `VxStream`-specific configurations that are missing need to be filled in before running and they look as follows as is:
```
VxStream {
    url = "https://www.vxstream-sandbox.com/"
    api = "https://www.vxstream-sandbox.com/api/"
    key = "..."
    secret = "..."
    environmentid = 100
    graceperiod = 300
    interval = 30
    timeout =  600
}
```

Note that the Python dependencies of `VxStream` are not handled by Cortex and need to be manually addressed with the following commands:
```
$ sudo apt install python3-pip
$ python3.5 -m pip install cortexutils python-magic requests
```

Alternatively, testing `VxStream` can be accomplished by issuing the following command with an example as input data and with the proper API and service settings provided in the configuration part:
```
$ python3.5 VxStream/vxstream.py <<< '{
    "dataType": "port",
    "data": "80",
    "config": {
        "url": "https://www.vxstream-sandbox.com/",
        "api": "https://www.vxstream-sandbox.com/api/",
        "key": "...",
        "secret": "...",
        "service": "Search"
    }
}'
```
Additional information on how to test analyzers can be retrieved from [CortexDocs/api/how-to-create-an-analyzer.md](https://github.com/CERT-BDF/CortexDocs/blob/master/api/how-to-create-an-analyzer.md).

# Resources
https://thehive-project.org/<br />
https://github.com/CERT-BDF/Cortex<br />
https://github.com/CERT-BDF/cortex-analyzers/<br />
https://github.com/CERT-BDF/CortexDocs<br />
https://github.com/CERT-BDF/TheHiveDocs/<br />
https://cert-bund-cortex-analyzers.readthedocs.io/en/latest/index.html
