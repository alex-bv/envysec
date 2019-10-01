import json
import logging
import os
import pathlib
import shlex


class Envyronment_Settings():
    """ Simple envySec settings manager.
    
    Used for configure ClamAV & Metadefender.
    """

    def __init__(self, path = 'settings.json', logging_level = 40):
        """ Settings manager is used to verify and fix current envySec settings.
        
        path -- path to file with secEnvyronment settings.
        logging_level -- log verbosity level. Log will be written into stdout.
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')
        
        self.envySettings = logging.getLogger('envySec SettingsEdit')
        self.envySettings.debug('__init__: Initializing class...')

        try:
            self.envySettings.debug('__init__: Reading settings...')
            with open(path, 'r') as settings_f:
                self.__settings = json.load(settings_f)
            
            self.envySettings.debug('__init__: Setting successfully read.')
            self.envySettings.debug('__init__: Verifying settings...')
            if self.__check_metadefender_api(self.settings["MetadefenderAPI"]) is False:
                self.envySettings.warning('__init__: Bad Metadefender API key received;')

                meta_api = self.register_metadefender_api()
                self.envySettings.debug('__init__: Successfully done gathering.')
                self.__new_settings = {
                    "MetadefenderAPI": meta_api
                }
            
                if self.__write_new_settings(settings = self.__new_settings, path = path) is False:
                    self.envySettings.warning('__init__: Skipping new setting file creation.')
                else:
                    self.envySettings.info('__init__: New setting file created.')

        except FileNotFoundError as fnotfound:
            self.envySettings.warning('__init__: Failed to open {}. File not found.'.format(path))
            self.envySettings.debug('__init__: FileNotFoundError args: ' + str(fnotfound.args))

            self.envySettings.info('__init__: Creating new settings.')
            self.envySettings.debug('__init__: Gathering settings.')

            meta_api = self.register_metadefender_api()
            self.envySettings.debug('__init__: Successfully done gathering.')
            self.__new_settings = {
                "MetadefenderAPI": meta_api
            }

            if self.__write_new_settings(settings = self.__new_settings, path = path) is False:
                self.envySettings.warning('__init__: Skipping new setting file creation.')
            else:
                self.envySettings.info('__init__: New setting file created.')
        except PermissionError as permdenied:
            self.envySettings.warning('__init__: Failed to open {}. Permissions denied!'.format(path))
            self.envySettings.debug('__init__: PermissionsError args: ' + str(permdenied.args))
            raise
            
    @property
    def settings(self) -> dict:
        """ Function is used to return envySec settings.

        Return new settings (dict) if old ones were not verified.
        Else return old ones (dict with).
        """

        self.envySettings.debug('settings: starting settings...')
        self.envySettings.info('settings: return settings.')
        try:
            self.envySettings.debug('settings: Trying to return new settings...')
            return self.__new_settings
        except AttributeError as attrerr:
            self.envySettings.debug('settings: Current settins would be returned.')
            return self.__settings

    @property
    def clam_config(self) -> dict:
        """ Return ClamAV scanner and updater paths.
        Automatically resolve ClamAV paths;

        Return dict with path to clamscan & freashclam;
        Looks like:
        {
            "Scanner": "/path/to/clamscan",
            "Updater": "C:\\Some path\\to\\freshclam.exe"
        },
        All objects in dict are strings.

        If detected OS is not supported, raise OSError (as most suitable error);
        """

        self.envySettings.debug('clam_config: starting clam_config...')
        self.envySettings.debug('clam_config: empty clam_conf;')
        clam_conf = {

        }

        self.envySettings.debug('clam_config: resolving ClamAV paths...')
        self.envySettings.debug('clam_config: detecting OS...')
        if os.name == 'posix':
            self.envySettings.info('clam_config: POSIX (Linux) OS detected.')
            
            # Priority: Path
            paths = {
                1: pathlib.Path("/usr/bin/"),
                2: pathlib.Path("/usr/sbin/"),
                3: pathlib.Path("/bin/"),
                4: pathlib.Path("/sbin/")
            }

            # Reverse is used to prevent prior path rewrite;
            for i in reversed([int(x) for x in paths.keys()]):
                if os.path.exists(paths[i].joinpath('clamscan')) is True:
                    self.envySettings.info('clam_config: ClamAV scanner detected;')
                    self.envySettings.debug('clam_config: ClamAV scanner path: {}'.format(str(paths[i].joinpath('clamscan'))))
                    self.envySettings.debug('clam_config: Path priority: {}'.format(i))
                    clam_conf["Scanner"] = str(paths[i].joinpath('clamscan'))
                if os.path.exists(paths[i].joinpath('freshclam')) is True:
                    self.envySettings.info('clam_config: ClamAV updater detected;')
                    self.envySettings.debug('clam_config: ClamAV updater path: {}'.format(str(paths[i].joinpath('freshclam'))))
                    self.envySettings.debug('clam_config: Path priority: {}'.format(i))
                    clam_conf["Updater"] = str(paths[i].joinpath('freshclam'))
    
        elif os.name == 'nt':
            self.envySettings.info('clam_config: NT (Windows) OS detected.')
            self.envySettings.debug('clam_config: resolving ClamAV paths...')

            # Priority: Path
            paths = {
                1: pathlib.PureWindowsPath("C:\\Program Files\\ClamAV"),
                2: pathlib.PureWindowsPath("C:\\Program Files (x86)\\ClamAV")
            }

            # Reverse is used to prevent prior path rewrite;
            for i in reversed(paths.keys()):
                if os.path.exists(paths[i].joinpath('clamscan.exe')) is True:
                    self.envySettings.info('clam_config: ClamAV scanner detected;')
                    self.envySettings.debug('clam_config: ClamAV scanner path: {}'.format(str(paths[i].joinpath('clamscan.exe'))))
                    self.envySettings.debug('clam_config: Path priority: {}'.format(i))
                    clam_conf["Scanner"] = str(paths[i].joinpath('clamscan.exe'))
                if os.path.exists(paths[i].joinpath('freshclam.exe')) is True:
                    self.envySettings.info('clam_config: ClamAV updater detected;')
                    self.envySettings.debug('clam_config: ClamAV updater path: {}'.format(str(paths[i].joinpath('freshclam.exe'))))
                    self.envySettings.debug('clam_config: Path priority: {}'.format(i))
                    clam_conf["Updater"] = str(paths[i].joinpath('freshclam.exe'))
        else:
            self.envySettings.critical('clam_config: unsupported platform detected;')
            raise OSError('Unsupported platform detected!') # Most suitable error, see docs;

        if clam_conf["Updater"] is None or clam_conf["Scanner"] is None:
            self.envySettings.critical('clam_config: Failed to resolve ClamAV paths.')
            raise FileNotFoundError('ClamAV was\'nt found.') # Most suitable error, see docs;
        else:
            self.envySettings.info('clam_config: ClamAV paths resolved.')
        return clam_conf


    def register_metadefender_api(self) -> str:
        """ Get Metadefender API key.

        Request to input API key manually and verify it\'s length.
        API key -- 32 char len string, containing 0-9, A-F;

        Return API key.
        It looks like: 1234567890ABCDEF1234567890ABCDEF
        """

        self.envySettings.debug('register_metadefender_api: starting register_metadefender_api...')
        self.envySettings.info('metadeferegister_metadefender_apinder_api: requesting API key...')
        
        apikey = str(input('Input Metadefender API key: '))
        self.envySettings.debug('register_metadefender_api: Checking API key...')
        while self.__check_metadefender_api(apikey) is False:
            self.envySettings.info('register_metadefender_api: API key is wrong. Requesting again...')
            apikey = str(input('Try again: '))

        return apikey

    def __check_metadefender_api(self, apikey: str) -> bool:
        """ Validate Metadefender API key.

        Function validate key length and chars;
        Every char should be [A-F, 0-9] and length should be 32;
        """

        self.envySettings.debug('__check_metadefender_api: starting __check_metadefender_api...')
        self.envySettings.info('__check_metadefender_api: Check API keys length.')
    
        if len(apikey) != 32:
            self.envySettings.critical('__check_metadefender_api: API key length is not valid.')
            self.envySettings.debug('__check_metadefender_api: API key length is not valid.')
            return False
        else:
            self.envySettings.debug('__check_metadefender_api: API key length is valid.')
            self.envySettings.info('__check_metadefender_api: Check API key chars.')
            for api_char in apikey:
                if api_char not in "1234567890ABCDEFabcdef":
                    self.envySettings.critical('__check_metadefender_api: API key is not valid.')
                    return False
        
        self.envySettings.info('__check_metadefender_api: API key validated.')
        return True


    def __write_new_settings(self, settings: dict, path: str) -> bool:
        """ Create new setting file.
        This function used to write new settings (dict) to file (path to).

        Return True if file created successfully;
        Return False if file already exist (FileExistsError detected) or permission denied (PermissionError detected);
        """

        self.envySettings.debug("__write_new_settings: starting __write_new_settings...")

        try:
            with open(path, 'w') as new_settings_f:
                json.dump(settings, new_settings_f)
        except FileExistsError as fexists:
            self.envySettings.warning('__write_new_settings: Failed to write into {}. File already exists.'.format(path))
            self.envySettings.debug('__write_new_settings: FileExistsError args: ' + str(fexists.args))
            return False
        except PermissionError as permdenied:
            self.envySettings.warning('__write_new_settings: Failed to write into {}. Permissions denied!'.format(path))
            self.envySettings.debug('__write_new_settings: PermissionsError args: ' + str(permdenied.args))
            return False
        else:
            self.envySettings.info('__write_new_settings: New settings file created.')
            return True
