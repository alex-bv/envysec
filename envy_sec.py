import argparse
import ipaddress
import logging
import os
import shlex
import sys

try:
    from modules import clamav
    from modules import metadefender
    from modules import envy_settings
    from modules import sql_management
except (ModuleNotFoundError, ImportError):
    print('\aFailed to start secEnvyronment.')
    print('Check if all dependencies present or if application integrity is OK.')
    raise


class ConsoleInterface():
    """ envySec command line interface class.
    Used to perform scans and update from command-line.
    
    Receive Metadefender API key, ClamAV path to config.
    Required packages (dependencies): 
        inherit dependencies from ClamAV class, Metadefender class and SQL exclude database management class.
        and: ipaddress, shlex
    
    Available methods:
        public: ip_scanner, file_scanner, update, add_exception, remove_exclude, get_exclude
        private: __show_ip_scan_results, __parse_metadefender_scan, __input_parse
    """

    def __init__(self, apikey = None, logging_level = 40):
        """ ClamAV & Metadefender control panel class.
        Used to manage scans.

        'apikey' - Metadefender API key, see metadefender.py for more;
        'logging_level' - verbosity of logging:
            0 - debug,
            30 - warnings,
            50 - critical.
            See 'logging' docs;
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')
        
        self.envyCLI_Log = logging.getLogger('EnvySec CLI')
        self.envyCLI_Log.debug('__init__: Initializing class...')

        try:
            self.envyCLI_Log.debug('__init__: Trying to get default settings...')
            self.envy_conf = envy_settings.Envyronment_Settings(path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'settings.json'), logging_level = logging_level)
        except FileNotFoundError:
            self.envyCLI_Log.debug('__init__: Default settings not found, looking for setting.json in current directory...')
            self.envy_conf = envy_settings.Envyronment_Settings(path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'settings.json'), logging_level = logging_level)

        self.clam = clamav.ClamAV(self.envy_conf.clam_config, logging_level = logging_level)
        self.metadef = metadefender.Metadefender(self.envy_conf.settings["MetadefenderAPI"], logging_level = logging_level)
        
        try:
            self.envyCLI_Log.debug('__init__: Trying to find exclude database...')
            self.exclude_db = sql_management.ExcludeDB(database = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'modules', 'exclude.db'))
        except FileNotFoundError:
            self.envyCLI_Log.debug('__init__: Database not found!')
            raise

        self.envyCLI_Log.debug('__init__: Class initialized.')


    def ip_scanner(self, targets: list, geo = False) -> bool:
        """ Scan IP address using Metadefender API.
        
        'targets' - list of IP to be scanned;
        'geo' - flag to show geo information about IP.

        Return True, if scan complete without errors.
        """

        self.envyCLI_Log.debug('ip_scanner: Starting IP scan.')
        self.envyCLI_Log.debug('ip_scanner: received targets: {}'.format(targets))

        targets = self.__targets_parse(targets) # Shlex targets (!)

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

    def __show_ip_scan_results(self, scan_results: dict, geo = False) -> bool:
        """ Parse data and print it to std.out. 
        
        'scan_results' - actual scan results (dict), received from Metadefender;
        'geo' - flag to show geo information about IP.

        Return True, if method complete without errors.
        """

        try:
            for ip in scan_results:
                print('{} scan results:'.format(ip))
                for source in scan_results[ip]['ScanData']:
                    print('\t{}: {}'.format(str(source), str(scan_results[ip]['ScanData'][source])))

                if geo is True:
                    print("""{} is placed in {}, {}, {}. Coordinates: {}, {}.""".format(
                                ip, 
                                scan_results[ip]['GeoData']["Country"], 
                                scan_results[ip]['GeoData']["Region"], 
                                scan_results[ip]['GeoData']["City"],
                                scan_results[ip]['GeoData']["Coordinates"]["Latitude"],
                                scan_results[ip]['GeoData']["Coordinates"]["Longitude"]
                            ))
        except IndexError as index_err:
            self.envyCLI_Log.critical('__show_ip_scan_results: Unexpected index error.')
            self.envyCLI_Log.debug('__show_ip_scan_results: IndexError args: {}'.format(str(index_err)))
            raise
        else:
            self.envyCLI_Log.debug('__show_ip_scan_results: Parsing done successfully.')
            return True

    def file_scanner(self, targets: list, exclude = None) -> bool:
        """ Scan file.
        
        'targets' - list of targets to be sanned;
        'exclude' - list of paths to be ignored.

        Return True, if scan complete successfully.
        Return False, if file does not exist or not found.
        """

        self.envyCLI_Log.debug('file_scanner: Starting file scan.')
        self.envyCLI_Log.debug('file_scanner: received targets: {}'.format(str(targets)))
        
        self.envyCLI_Log.debug('file_scanner: getting exclude list...')
        exclude = self.exclude_db.get_exception()
        self.envyCLI_Log.debug('file_scanner: exclude list: {}'.format(exclude))

        print('Scanning...') # This may take a while...

        self.envyCLI_Log.debug('file_scanner: parsing targets...')
        targets = self.__targets_parse(targets) # Shlex targets (!)
        self.envyCLI_Log.debug('file_scanner: targets parsed.')

        self.envyCLI_Log.debug('file_scanner: checking exclude list.')
        if exclude != []: # Check if exclude is defined. Used to prevent empty arg.
            self.envyCLI_Log.debug('file_scanner: getting exclude list.')
            exclude = self.exclude_db.get_exception()
            self.envyCLI_Log.debug('file_scanner: exclude list received.')

        self.envyCLI_Log.debug('file_scanner: checking targets existence...')
        for target in targets:
            self.envyCLI_Log.debug('file_scanner: Start {} existence check.'.format(target))
            if os.path.exists(target.strip('\'\"')) is False:
                self.envyCLI_Log.error('file_scanner: {} does not exist or might not be accessed.'.format(target))
                print('\a{} does not exist.'.format(str(target)))
                return False # Just remove 'target' from targets and try to continue

        if exclude != []:
            self.envyCLI_Log.debug('file_scanner: checking targets existence...')
            for exception in exclude:
                self.envyCLI_Log.debug('file_scanner: Start {} existence check.'.format(target))
                if os.path.exists(exception.strip('\'\"')) is False:
                    self.envyCLI_Log.error('file_scanner: {} does not exist or might not be accessed.'.format(target))
                    print('{} does not exist, passing anyway.'.format(exception))

        self.envyCLI_Log.debug('file_scanner: starting {}  scanning...'.format(target))
        for i in self.clam.scan(targets = targets, exclude = exclude):
            if str(i).strip().endswith('FOUND') is True:
                i = i.split(': ')[0]

                self.envyCLI_Log.info('file_scanner: {} considered suspicious, starting Metadefender scan.'.format(i))
                self.envyCLI_Log.debug('file_scanner: Starting scanning by hash...')
                meta_response = list(self.metadef.scan_hash(i))
                if False in meta_response:
                    self.envyCLI_Log.debug('file_scanner: Hash scan failed, sending file...')
                    scan_result, scan_details = self.metadef.scan_file(i)
                    self.envyCLI_Log.debug('file_scanner: Response received, parsing...')
                    self.__parse_metadefender_scan(i, scan_result, scan_details)
                    self.envyCLI_Log.debug('file_scanner: Parsing complete.')
                else:
                    self.envyCLI_Log.debug('file_scanner: Hash scan succeed.')
                    self.envyCLI_Log.debug('file_scanner: Response received, parsing...')
                    self.__parse_metadefender_scan(i, meta_response[0], meta_response[1])
                    self.envyCLI_Log.debug('file_scanner: Parsing complete.')
            elif i is None:
                self.envyCLI_Log.debug('file_scanner: Process ended without output.')
                self.envyCLI_Log.info('file_scanner: Process ended without output.')
            else:
                self.envyCLI_Log.info('file_scanner: Unexpected behaviour: {}'.format(i))
                return False

        self.envyCLI_Log.debug('file_scanner: Scan complete.')
        return True

    def __parse_metadefender_scan(self, target: str, scan_result: dict, scan_details: dict) -> bool:
        """ Parse data and print it to std.out. 
        
        'target' - path to scanned file;
        'scan_result' - actual file scan result, received from Metadefender;
        'scan_details' - meta information about performed by Metadefender scan.

        Return True if complete without errors.
        """

        self.envyCLI_Log.debug('__parse_metadefender_scan: Starting parsing Metadefender response.')
        self.envyCLI_Log.debug('__parse_metadefender_scan: parsing response for {}.'.format(target))

        print('Results for {}:'.format(target))
        print('\tTotal detections: {}'.format(scan_details["TotalDetections"]))
        for av in scan_result:
            print('\t\t{}: {}'.format(av, scan_result[av]))
        
        self.envyCLI_Log.debug('__parse_metadefender_scan: Parsing complete.')
        return True

    def update(self, verbose = False) -> bool:
        """ Simple update command.
        Backend defined at 'clamav.py'.

        'verbose' - flag to be verbose. If True, will print all 'freshclam' output.

        Return True if update complete successfully.

        For update configuration details see 'config.json' and 'freshclam.conf';
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


    def add_exception(self, targets: list) -> bool:
        """ Add path to exclude database. 
        Backend defined at 'sql_management.py'.

        'targets' - list of paths to be added to exclude list.

        Return True if path had been successfully added to exclude list.
        Return False if path had\'nt been added.
        """

        self.envyCLI_Log.debug('add_exception: Parsing targets...')
        targets = self.__targets_parse(targets) # Shlex targets (!)
        self.envyCLI_Log.debug('add_exception: Targets parsed.')
        
        self.envyCLI_Log.debug('add_exception: Adding exception...')
        for target in targets:
            if self.exclude_db.add_exception(target) is True:
                self.envyCLI_Log.debug('add_exception: Exclusion added.')
                return True
            else:
                self.envyCLI_Log.warning('add_exception: Failed to add exception.')
                return False

    def remove_exception(self, targets: list) -> bool:
        """ Remove path from exclude database.
        
        'targets' - list of paths to be removed from exclude list.

        Return True if path had been successfully removed from exclude list.
        """

        self.envyCLI_Log.debug('remove_exception: Checking targets...')
        targets = self.__targets_parse(targets) # Shlex targets (!)
        self.envyCLI_Log.debug('remove_exception: Targets removed.')

        self.envyCLI_Log.debug('remove_exception: Removing exception...')
        for target in targets:
            if self.exclude_db.remove_exception(target) is True:
                self.envyCLI_Log.debug('remove_exception: Exception removed.')
            else:
                self.envyCLI_Log.info('remove_exception: Failed to remove exception.')
        
        return True

    def get_exclude(self) -> bool:
        """ Print exclude list.
        
        Return True, if function had been complete successfully.
        """

        self.envyCLI_Log.debug('get_exclude: Getting exclude list...')
        for exception in self.exclude_db.get_exception():
            self.envyCLI_Log.debug('get_exclude: {} in exclude list;'.format(exception))
            print(exception)

        self.envyCLI_Log.debug('get_exclude: finished getting exceptions.')
        return True

    def __targets_parse(self, targets: str) -> list:
        """ Parse comma-separated line to list.

        'targets' - list of strings.

        Return list of arguments (strings).
        Raise AttributeError if targets can\'t be parsed.
        """

        self.envyCLI_Log.debug('__input_parse: Parsing {}...'.format(targets))
        try:
            return [shlex.quote(i) for i in targets]
        except AttributeError as attr_err:
            self.envyCLI_Log.warning('__input_parse: Can\'t parse {}.'.format(targets))
            self.envyCLI_Log.info('__input_parse: Probably wrong targets type.')
            self.envyCLI_Log.debug('__input_parse: AttributeError args: {}'.format(attr_err))
            print('Can\'t parse {}, probably wrong targets type.'.format(targets))
            raise
        else:
            self.envyCLI_Log.info('__input_parse: {} was\'nt parsed, but no error occurred.'.format(targets))
            self.envyCLI_Log.info('__input_parse: Raising AttributeError due to parsing fail.')
            raise AttributeError('Can\'t parse {}!'.format(targets))



if __name__ == '__main__':

    logging.basicConfig(level = 10,
                        filename = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'secEnvyronment.log'),
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
    parser.add_argument('-F', '--scan-file', type=str, action='append', nargs='+', metavar='PATH',
                        help="""
                        Default scanning options will show only infected files.
                        Default path scanning behavior will recursively scan path.
                        If infected file found, it will be scanned using OPSWAT Metadefender.
                        
                        Example: envy_sec.py --scan-file C:\\* 
                            or envy_sec.py -S D:\\SomeFolder\\SomeFile.exe
                        """)
    parser.add_argument('-I', '--scan-ip', type=str, nargs='+', action='append',
                        metavar='IP', help="""
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
                        metavar='PATH', help="""
                        Add path to exclude list. Files in exclude list will not be scanned by ClamAV.
                        
                        Example: envy_sec.py --add-exception C:\\
                            or envy_sec.py -E D:\\SomeFolder\\SomeFile.exe
                        """)
    parser.add_argument('-R', '--remove-exception', type=str, nargs='+', action='append',
                        metavar='PATH', help="""
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
        envy_cli = ConsoleInterface() ## class will initialize Metadefender and ClamAV automatically.
        envy_sec.info('Initialize work:')
        if args.update is True:
            envy_sec.info('Starting update.')
            envy_cli.update(verbose = True)
            envy_sec.info('Update complete.')

        if args.scan_ip != None:
            envy_sec.info('Starting IP scan.')
            envy_sec.debug('IP Scanner arguments: {}'.format(args.scan_ip))
            envy_cli.ip_scanner(args.scan_ip[0], geo = True)
            envy_sec.info('IP scan complete.')

        if args.scan_file != None:
            envy_sec.info('Starting file scan.')
            envy_sec.debug('File Scanner arguments: {}'.format(args.scan_file))
            envy_cli.file_scanner(args.scan_file[0])
            envy_sec.info('File scan complete.')

        if args.add_exception != None:
            envy_sec.info('Adding exception to exclude list.')
            envy_sec.debug('Add exception arguments: {}'.format(args.add_exception))
            envy_cli.add_exception(args.add_exception[0])
            envy_sec.info('Exception added.')

        if args.remove_exception != None:
            envy_sec.info('Removing exception from exclude list.')
            envy_sec.debug('Remove exception arguments: {}'.format(args.remove_exception))
            envy_cli.remove_exception(args.remove_exception[0])
            envy_sec.info('Exception removed.')

        if args.get_exceptions is True:
            envy_sec.info('Getting exceptions list.')
            envy_cli.get_exclude()
            envy_sec.info('Exceptions list received.')

        if args.web is True:
            pass

    envy_sec.debug('secEnvyronment: done.')
