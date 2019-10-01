import argparse
import ipaddress
import logging
import os
import sys

try:
    from modules import clamav
    from modules import metadefender
    from modules import envy_settings
except (ModuleNotFoundError, ImportError):
    print('Failed to start secEnvyronment.')
    raise


class ConsoleInterface():
    """ envySec command line interface class.
    Used to perform scans and update from command-line.
    
    Receive Metadefender API key, ClamAV path to config.
    Required packages (dependencies): 
        inherit dependencies from ClamAV class and Metadefender Class
        and: ipaddress
    """

    def __init__(self, apikey = None, logging_level = 40):
        """ apikey -- Metadefender API key, see metadefender.py for more;
        logging_level -- verbosity of logging (0 - debug, 30 - warnings. See logging docs);
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')
        
        self.envyCLI_Log = logging.getLogger('EnvySec CLI')
        self.envyCLI_Log.debug('__init__: Initializing class...')

        self.envy_conf = envy_settings.Envyronment_Settings(logging_level = logging_level)
        self.clam = clamav.ClamAV(self.envy_conf.clam_config, logging_level = logging_level)
        self.metadef = metadefender.Metadefender(self.envy_conf.settings["MetadefenderAPI"], logging_level = logging_level)

        self.envyCLI_Log.debug('__init__: Class initialized.')


    def ip_scanner(self, targets: list, geo = False) -> bool:
        """ Scan IP adress using Metadefender API.
        Backend defined at metadefender.py.
        
        Return dict with scan and geo data.
        Dict structure:
            scan_dump = {
                "1.2.3.4": {
                    "ScanData": [...],
                    "GeoData": [...]
                },
                "4.5.6.7": {
                    "ScanData": [...],
                    "GeoData": [...]
                },
                ...
        }

        For more details see official Metadefender documentations.
        """

        self.envyCLI_Log.debug('ip_scanner: Starting IP scan.')
        self.envyCLI_Log.debug('ip_scanner: received targets: {}'.format(targets))

        if type(targets) == str:
            targets = [targets]
        elif type(targets) == list and type(targets[0]) == list:
            targets = targets[0]

        self.envyCLI_Log.debug('ip_scanner: starting ip_scanner...')
        for target in targets:
            try:
                ip_addr = ipaddress.ip_interface(target)
            except ipaddress.AddressValueError as wrong_ip:
                print('envy_sec: Invalid IP address!')
                self.envyCLI_Log.error('ip_scanner: Invalid IP address: {}!'.format(targets))
                self.envyCLI_Log.debug('ip_scanner: ipaddress.AddressValueError args: {}'.format(wrong_ip))
                raise
            except ipaddress.NetmaskValueError as wrong_mask:
                print('envy_sec: Invalid IP mask!')
                self.envyCLI_Log.error('Iip_scanner: invalid IP mask: {}!'.format(targets))
                self.envyCLI_Log.debug('ip_scanner: ipaddress.NetmaskValueError args: {}'.format(wrong_mask))
                raise
            
            scan_dump = dict()
            for ip in ip_addr.network:
                ip = str(ip)

                self.envyCLI_Log.debug('ip_scanner: Gathering information for {}...'.format(ip))
                if ipaddress.ip_address(ip).is_global is True:
                    scan_data, geo_data = self.metadef.scan_ip(ip)

                    scan_dump[ip] = dict()
                    scan_dump[ip]['ScanData'] = scan_data
                    scan_dump[ip]['GeoData'] = geo_data
                    self.envyCLI_Log.info('ip_scanner: Gathering info for {} successfully done.'.format(ip))
                else:
                    self.envyCLI_Log.warning('Invalid IP address: {}!'.format(ip))
                    print('{} is not global IP, so not scanned.'.format(ip))
            
            self.envyCLI_Log.debug('ip_scanner: Calling for __show_ip_scan_results...')
            if self.__show_ip_scan_results(scan_dump, geo = geo) is True:
                self.envyCLI_Log.info('ip_scanner: Scanning {} is done.'.format(ip))
        
        self.envyCLI_Log.info('ip_scanner: Scan complete.')
        return True

    def __show_ip_scan_results(self, scan_results: dict, geo = True) -> bool:
        """ Parse data and print it to std.out. """

        try:
            for ip in scan_results:
                print('{} scan results:'.format(ip))
                for source in scan_results[ip]['ScanData']:
                    print('\t' + str(source) + ': ' + str(scan_results[ip]['ScanData'][source]))

                if geo is True:
                    print("""{} is placed in {}, {}, {}. 
                            Coordinates: {}, {}.""".format(ip, 
                                                            scan_results[ip]['GeoData']["Country"]), 
                                                            scan_results[ip]['GeoData']["Region"], 
                                                            scan_results[ip]['GeoData']["City"],
                                                            scan_results[ip]['GeoData']["Coordinates"]["Latitude"],
                                                            scan_results[ip]['GeoData']["Coordinates"]["Longitude"])
        except IndexError as ierr:
            self.envyCLI_Log.critical('__show_ip_scan_results: Unexpected index error.')
            self.envyCLI_Log.debug('__show_ip_scan_results: IndexError args: ' + str(ierr))
            raise
        else:
            self.envyCLI_Log.debug('__show_ip_scan_results: Parsing done successfully.')
            return True


    def file_scanner(self, targets: list) -> bool:
        """ Scan file. 
        
        Return True if scan complete successfully.
        Return False if file does not exist or not found.

        For more details see official Metadefender documentations.
        """

        self.envyCLI_Log.debug('file_scanner: Starting file scan.')
        self.envyCLI_Log.debug('file_scanner: received targets: ' + str(targets))

        print('Scanning...') # This may take a while...

        self.envyCLI_Log.debug('file_scanner:  checking variable type.')
        if type(targets) == str:
            targets = [targets]
        elif type(targets) == list and type(targets[0]) == list:
            targets = targets[0]
        self.envyCLI_Log.debug('file_scanner:  variable type checked.')

        self.envyCLI_Log.debug('file_scanner: starting file_scanner...')
        for target in targets:
            self.envyCLI_Log.debug('file_scanner: Start {} scan.'.format(target))
            if os.path.exists(target) is False:
                self.envyCLI_Log.error('file_scanner: {} does not exist or might not be accessed.'.format(target))
                print('\a' + str(target) + ' does not exist.')
                return False

        self.envyCLI_Log.debug('file_scanner: {} exist, starting ClamAV scanning.'.format(target))
        for i in self.clam.scan(targets):
            if str(i).endswith('FOUND\r') is True:
                i = i.split(': ')[0]

                self.envyCLI_Log.info('file_scanner: {} considered suspicious, starting Metadefender scan.'.format(target))
                self.envyCLI_Log.debug('file_scanner: Starting scanning by hash...')
                meta_response = self.metadef.scan_hash(i)
                if meta_response is False:
                    self.envyCLI_Log.debug('file_scanner: Hash scan failed, sending file...')
                    scan_result, scan_details = self.metadef.scan_file(i)
                    self.envyCLI_Log.debug('file_scanner: Response received, parsing...')
                    self.__parse_metadefender_scan(i, scan_result, scan_details)
                    self.envyCLI_Log.debug('file_scanner: Parsing complete.')
                else:
                    self.envyCLI_Log.debug('file_scanner: Hash scan successed.')
                    self.envyCLI_Log.debug('file_scanner: Response received, parsing...')
                    self.__parse_metadefender_scan(i, meta_response[0], meta_response[1])
                    self.envyCLI_Log.debug('file_scanner: Parsing complete.')
            else:
                self.envyCLI_Log.info('file_scanner: Unexpected behaviour: {}'.format(i))

        self.envyCLI_Log.debug('file_scanner: Scan complete.')
        return True

    def __parse_metadefender_scan(self, target: str, scan_result: dict, scan_details: dict) -> bool:
        """ Parse data and print it to std.out. """

        self.envyCLI_Log.debug('__parse_metadefender_scan: Starting parsing Metadefender response.')
        self.envyCLI_Log.debug('__parse_metadefender_scan: parsing response for ' + target + '.')

        print('Results for {}:'.format(target))
        print('\tTotal detections: {}'.format(scan_details["TotalDetections"]))
        for av in scan_result:
            print('\t\t{}: {}'.format(av, scan_result[av]))
        
        self.envyCLI_Log.debug('__parse_metadefender_scan: Parsing complete.')
        return True


    def add_exlcude(self, target: str) -> bool:
        """
        """

        self.clam.add_exception(target)
    
    def remove_exlcude(self, target: str) -> bool:
        """
        """

        self.clam.remove_exception(target)

    def get_exlcude(self) -> bool:
        """
        """

        for exception in self.clam.get_exception():
            print(exception)


    def update(self, verbose = False) -> bool:
        """ Simpe update command.
        Backend defined at clamav.py.

        Return True if update complete successfully.

        For update configuration details see config.json and freshclam.conf;
        For more details see official ClamAV documentations.
        """

        self.envyCLI_Log.debug('Signatures update started.')
        print('\tUpdating ClamAV signatures...')
        
        for update_output in self.clam.update():
            if verbose is True:
                print(update_output)
            else:
                pass

        self.envyCLI_Log.debug('Signatures update done.')
        print('\tDone.')
        return True


if __name__ == '__main__':

    logging.basicConfig(level = 0,
                        filename = os.path.abspath(os.path.dirname(__file__) + 'secEnvyronment.log'),
                        filemode = 'a',
                        format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                        datefmt='%d.%m.%Y %H:%M:%S')
    
    envy_sec = logging.getLogger('secEnvyronment')
    envy_sec.debug('Initialize Application...')

    parser = argparse.ArgumentParser(prog='secEnvyronment', epilog="""
                                    (c) EnvySec Dev, 2019.
                                    """, description="""
                                    This software is used to simplify ClamAV usage and automatize detect verification using Metadefender service.
                                    """)
    parser.add_argument('-F', '--scan-file', type=str, action='append', nargs='+', metavar='<PATH>',
                        help="""
                        Default scanning options will show only infected files.
                        Default path scanning behavior will recursively scan path.
                        If infected file found, it will be scanned using OPSWAT Metadefender.
                        
                        Example: envy_sec.py --scan-file C:\\* 
                            or envy_sec.py -S D:\\SomeFolder\\SomeFile.exe
                        """)
    parser.add_argument('-I', '--scan-ip', type=str, nargs='+', action='append',
                        metavar='<IPs>', help="""
                        IP will be scanned using OPSWAT Metadefender.
                        
                        Example: envy_sec.py --scan-ip 8.8.8.8 
                            or envy_sec.py -I 8.8.8.0\\24
                        """)
    parser.add_argument('-U', '--update', action='store_true', help="""
                        Update mode will update ClamAV Database.
                        (!) To Upgrade ClamAV itself download and install it manually.
                        
                        Example: envy_sec.py --update
                            or envy_sec.py -U
                        """)
    parser.add_argument('-E', '--add-exception', type=str, nargs='+', action='append',
                        metavar='<PATH>', help="""
                        Add path to exclude list. Files in exclude list will not be scanned by ClamAV.
                        
                        Example: envy_sec.py --add-exception C:\\
                            or envy_sec.py -E D:\\SomeFolder\\SomeFile.exe
                        """)
    parser.add_argument('-R', '--remove-exception', type=str, nargs='+', action='append',
                        metavar='<PATH>', help="""
                        Remove exception from exclude list.
                        
                        Example: envy_sec.py --remove-exception C:\\
                            or envy_sec.py -R D:\\SomeFolder\\SomeFile.exe
                        """)
    parser.add_argument('-G', '--get-exceptions', action='store_true', help="""
                        List all secEnvyronment exceptions.
                        
                        Example: envy_sec.py --get-exceptions
                            or envy_sec.py -G
                        """)
    parser.add_argument('-W', '--web', action='store_true', help="""
                        Start Web-based GUI.
                        
                        Example: envy_sec.py --web
                            or envy_sec.py -W
                        """)

    envy_sec.info('Parsing arguments...')
    args = parser.parse_args()
    envy_sec.debug('...parsing succeed.')
    
    if args.web == True:
        pass
    else:
        envy_sec.info('Initialize Command Line Interface (CLI).')
        envy_cli = ConsoleInterface() ## CLI initialize Metadefender and ClamAV itself.

        args.get_exception = True

        envy_sec.info('Initialize work:')
        if args.update is True:
            envy_sec.info('Starting update.')
            envy_cli.update(verbose = True)
            envy_sec.info('Update complete.')

        if args.scan_ip != None:
            envy_sec.info('Starting IP scan.')
            envy_cli.ip_scanner(args.scan_ip, geo = True)
            envy_sec.info('IP scan complete.')

        if args.scan_file != None:
            envy_sec.info('Starting file scan.')
            envy_cli.file_scanner(args.scan_file)
            envy_sec.info('File scan complete.')

        if args.add_exception != None:
            envy_sec.info('Adding exception to exclude list.')
            envy_cli.add_exlcude(args.scan_file)
            envy_sec.info('Exception added.')

        if args.remove_exception != None:
            envy_sec.info('Removing exception from exclude list.')
            envy_cli.remove_exlcude(args.scan_file)
            envy_sec.info('Exception removed.')

        if args.get_exceptions is True:
            envy_sec.info('Getting exceptions list.')
            envy_cli.get_exlcude()
            envy_sec.info('Exceptions list received.')

        if args.web is True:
            pass

    envy_sec.debug('secEnvyronment work complete.')