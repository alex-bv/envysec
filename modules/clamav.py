import datetime
import logging
import os
import pathlib
import queue
import sqlite3
import subprocess # WARNING, POSSIBLE SECURITY ISSUE: Bandit report: 'Consider possible security implications associated with subprocess module.'
import threading


class ClamAV():
    """ ClamAV command class. This is not a stand-alone scanner.
    It depends on original ClamAV and used to perform an easier-control.

    Available methods:
        public: scan, update
        private: __scan, __update, __call_proc, __resolve_path

    Required packages (dependencies): 
        built-in: datetime, logging, os, pathlib, queue, sqlite3, subprocess, threading
        3-d party: -

    To perform a scan, it uses sys.Popen to call for a ClamAV bin with a customized args.
    For storring exlclude database uses sqlite3.

    ClamAV official site (2018): www.clamav.net
    Cisco (ClamAV owner and maintainer) official site (2018): www.cisco.com
    """

    def __init__(self, config: dict, logging_level = 30):
        """ ClamAV class used to control ClamAV app.

        'config' - dictionary with paths to ClamAV bins (freshclam & clamscan);
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
        
        self.ClamLog = logging.getLogger('ClamAV')
        self.ClamLog.debug('__init__: Initializing class...')

        self.configuration = config
        self.clamav_queue = queue.Queue()

        self.ClamLog.debug('__init__: Class initialized.')


    def scan(self, targets: list, args = ['-i', '-r', '--no-summary', '--alert-exceeds-max=no'], exclude = None) -> "yield str":
        """ Method used to perform a ClamAV scan.

        'targets' - list of paths to be scanned;
        'args' - list of arguments to be sent to ClamAV;
        'exclude' - list of paths not to be scanned.

        Return False if file/dir (target) does not exists, might not be accessed
        or in exclude list (see config).
        If target exist and not in exclude list, it will call for ClamAV
        and yield it\'s output.

        Argument 'target' is a file or dir to be scanned.
        'Args' are arguments list to be sent to ClamAV bin
        (see ClamAV documentations for more).
        Argument 'Exclude' is a list with valid paths not to be scanned.
        Every in 'Exclude' will be formated individually (file or dir type definition, formation to '--exclude' or '--exclude-dir')

        Default scanner behaveour is (arguments descriptions):
            show only infected files (-i). It also will show all files, that might not be accessed by ClamAV;
            scan recursively (-r). It usefull for scanning whole dir;
            do not show summary at the end of scan (--no-summary);
            do not show 'exceeds max' errors (--alert-exceeds-max=no).
        """

        self.ClamLog.debug('scan: Starting scan.')

        def __parse_line(line: str) -> bool:
            """ Check if 'line' report thread found.
            'line' must ends with 'FOUND' and starts with path to infected file.

            Return True if both conditions are met;
            Return False if one of conditions was not met.
            """

            self.ClamLog.debug('scan: __parse_line: Checking {}'.format(line))
            if line.strip().endswith(' FOUND') is True and os.path.exists(line.split(': ')[0]) is True:
                self.ClamLog.debug('scan: __parse_line: {} met conditions, return True.'.format(line))
                return True
            else:
                self.ClamLog.debug('scan: __parse_line: {} have not met conditions, return False.'.format(line))
                return False

        self.ClamLog.debug('scan: Retrieving exceptions...')
        if exclude is not None and exclude != []:
            exception_list = str() # Used to translate exclude elements to string; example: exclude = ['a/b/c'] -> except_list = '--exclude=a/b/c'
            for exception in exclude:
                exception_path = self.__resolve_path(exception)

                if os.path.isdir(exception_path) is True:
                    exception_list += '--exclude-dir={}'.format(exception_path)
                elif os.path.isfile(exception_path) is True:
                    exception_list += '--exclude={}'.format(exception_path)
                elif os.path.islink(exception_path) is True:
                    self.ClamLog.info('scan: {} is a symbolic link, trying to follow...'.format(exception_path))
                    exception_list += '--exclude={}'.format(exception_path)
                elif os.path.ismount(exception_path) is True:
                    self.ClamLog.info('scan: {} is a mount point, trying to continue...'.format(exception_path))
                    exception_list += '--exclude={}'.format(exception_path)
                else:
                    self.ClamLog.warning('scan: type of {} is not defined, trying to continue...'.format(exception_path))
                    exception_list += '--exclude={}'.format(exception_path)
                exception_list += ' ' # Add space, ClamAV does\'nt support comma-separated lists.
            args.append(exception_list.strip()) # Strip whitespace at the end;

        self.ClamLog.debug('scan: Checking targets...')
        targets = [self.__resolve_path(target) for target in targets]

        _targets = list() # Prevent empty 'targets' list to be insert in 'args'.
        for target in targets: 
            if os.path.exists(target) is False:
                self.ClamLog.info('scan: {} does not exists, so could not be scanned.'.format(target))
            elif target in exclude:
                self.ClamLog.info('scan: {} is in exclude list, so will not be scanned.'.format(target))
            else:
                self.ClamLog.debug('scan: {} added to scan list.'.format(target))
                _targets.append(target)

        if len(_targets) > 0: # Prevent empty 'targets' list to be insert in 'args'.
            for target in _targets:
                args.insert(0, target)
        else:
            self.ClamLog.error('scan: No targets to be scanned has been specified!')
            self.ClamLog.info('scan: Maybe target in exclude list or does not exists?')
            raise ValueError('''
                            No targets to be scanned has been specified!
                            Maybe targets in exclude list or not exists?
                        ''')

        self.ClamLog.debug('scan: Starting work...')
        for line in self.__call_proc(self.__scan, args = args):

            self.ClamLog.debug('scan: Init __parse_line...')
            if __parse_line(line) is True:
                self.ClamLog.debug('scan: __parse_line: line reports True.')
                self.ClamLog.warning('scan: FOUND: {}'.format(str(line)))
                yield line
            else:
                self.ClamLog.debug('scan: __parse_line: line reports False.')
                self.ClamLog.warning('unknown line: {}'.format(str(line)))

    def update(self, args = ['--stdout', '--show-progress']) -> "yield output":
        """ Method used to perform a ClamAV database update.
        It yield\'s ClamAV Update output.

        Some Linux systems don\'t require manual update.
        (see 'freshclamd' state)

        'args' are arguments list to be sent to ClamAV bin
        (see ClamAV documentations for more).

        For more information about ClamAV, see ClamAV documentations.
        Default update behaveour is (arguments descriptions):
            out any lines to stdout, not to stderr (--stdout);
            show update progress (--show-progress).
        """

        self.ClamLog.info('update: ClamAV Update started.')
        for line in self.__call_proc(self.__update, args=args):
            self.ClamLog.info(line.strip())
            yield line


    def __scan(self, *args) -> bool:
        """ 'Lower-level' method (module) of scan. 
        Method used to call for ClamAV scanner bin.
        It fact, it used to call for ClamAV bin (for example: clamscan.exe on Windows)
        and put it\'s output to pipe.
        
        Return True if scan complete successfully.
        Raise OSError if OS or memory errors occurred.
        Raise ValueError if wrong internal arguments or wrong bin\'s path received.

        Args are arguments list to be sent to ClamAV bin.
        Available arguments might be found at ClamAV scan documentations or by using --help.
        """

        self.ClamLog.debug('__scan: Scan started.')
        args = list(args)
        
        try: # Bandit report: 'subprocess call - check for execution of untrusted input.', see line 7.
            with subprocess.Popen([self.configuration["Scanner"]] + args, stdout=subprocess.PIPE) as scanp:
                self.ClamLog.debug('__scan: Subprocess opened. (subprocess.Popen)')
                for line in iter(scanp.stdout.readline, b''):
                    self.clamav_queue.put(line)
        except MemoryError as memory_err:
            self.ClamLog.critical('__scan: Failed to perform __scan. Probably not enough memory.')
            self.ClamLog.debug('__scan: MemoryError arguments: {}'.format(str(memory_err.args)))
            raise OSError('System may not perform scan, probably not enough memory.', memory_err.args)
        except OSError as os_err:
            self.ClamLog.critical("""__scan: Failed to call for __scan. Probably, module subprocess.Popen 
                                received wrong bin\'s filename.""")
            self.ClamLog.debug('__scan: OSError arguments: {}'.format(str(os_err.args)))
            raise ValueError('System may not perform scan, probably not system error raised.', os_err.args)
        except ValueError as value_err:
            self.ClamLog.critical("""__scan: Failed to call for __scan. Probably, module subprocess.Popen 
                                called with invalid arguments.""")
            self.ClamLog.debug('__scan: ValueError arguments: {}'.format(str(value_err.args)))
            raise ValueError('Failed to spawn process, probably wrong internal arguments received.', value_err.args)
        else:
            self.ClamLog.debug('__scan: Scan done.')
            return True

    def __update(self, *args) -> bool:
        """ 'Lower-level' database (signatures) update method.
        It call for update bin, bin's path taken from configuration.
        It fact, it used to call for ClamAV bin (for example: freshclam.exe on Windows)
        and put it\'s output to pipe.

        Return True if update complete successfully.
        Raise OSError if OS or memory errors occurred.
        Raise ValueError if wrong internal arguments or wrong bin\'s path received.

        Args are arguments list to be sent to ClamAV bin.
        Available arguments might be found at ClamAV update documentations or by using --help.
        """

        self.ClamLog.debug('__update: Update in fact started.')
        args = list(args)

        try: # WARN: Bandit report: 'subprocess call - check for execution of untrusted input.', see line 7.
            with subprocess.Popen([self.configuration["Updater"]] + args, stdout=subprocess.PIPE) as updatep:
                self.ClamLog.debug('__update: Subprocess opened. (subprocess.Popen)')
                for line in iter(updatep.stdout.readline, b''):
                    self.clamav_queue.put(line)
        except OSError as os_err:
            self.ClamLog.critical("""__update: Failed to call for __update. Probably, module subprocess.Popen 
                                received wrong bin\'s filename.""")
            self.ClamLog.debug('__update: OSError arguments: {}'.format(str(os_err.args)))
            raise ValueError('Failed to spawn process, probably wrong bin\'s filename received.', os_err.args)
        except ValueError as value_err:
            self.ClamLog.critical("""__update: Failed to call for __update. Probably, module subprocess.Popen 
                                called with invalid arguments.""")
            self.ClamLog.debug('__update: ValueError arguments: {}'.format(str(value_err.args)))
            raise ValueError('Failed to spawn process, probably wrong internal arguments received.', value_err.args)
        except MemoryError as memory_err:
            self.ClamLog.critical('__update: Failed to perform __update. Probably not enough memory.')
            self.ClamLog.debug('__update: MemoryError arguments: {}'.format(str(memory_err.args)))
            raise MemoryError('System may not perform update, probably not enough memory.', memory_err.args)
        else:
            self.ClamLog.debug('__update: Update done.')
            return True


    def __call_proc(self, work: 'function', args = None) -> "yield str":
        """ Initialize main work thread.
        It used to call for main working function (like scan or update).

        'work' - name of function to be called.
        'args' - list of arguments to be sent to work function.

        Yield work\'s function output.
        """

        self.ClamLog.debug('__call_proc: Initialize work thread.')
        if args is None:
            self.ClamLog.debug('__call_proc: No arguments received.')
            args = list()

        self.ClamLog.debug('__call_proc: Creating thread.')
        work_thread = threading.Thread(target = work, args = args, daemon = True)
        self.ClamLog.debug('__call_proc: Starting thread.')
        work_thread.join() # Use 'join' to prevent endless scan
        self.ClamLog.debug('__call_proc: Work thread Initialized.')

        self.ClamLog.debug('__call_proc: Looking for output.')
        while work_thread.is_alive():
            try:
                line = self.clamav_queue.get_nowait()
                line = line.decode('utf-8').strip()
                self.ClamLog.debug('__call_proc: Output: {}'.format(line))
            except queue.Empty:
                pass
            else:
                self.ClamLog.debug('__call_proc: Yield {}.'.format(line))
                yield line
        else:
            self.ClamLog.debug('__call_proc: Process ended without any output.')
            return None

    def __resolve_path(self, path: str) -> str:
        """ Resolve path string to absolute path.

        Used to resolve symlinks and return absolute path.
        """

        self.ClamLog.info('__resolve_path: Starting path resolver.')
        self.ClamLog.debug('__resolve_path: Resolving {}...'.format(path))

        try:
            path = pathlib.Path(path)
        except NotImplementedError as path_resolve_bad_python_err:
            self.ClamLog.warning('__resolve_path: Failed to resolve {}.'.format(path))
            self.ClamLog.info('__resolve_path: TIP: Probably OS is not supported.')
            self.ClamLog.debug('__resolve_path: NotImplementedError occurred, log: {}'.format(str(path_resolve_bad_python_err.args)))
            self.ClamLog.info('__resolve_path: Trying to run anyway...')
            return str(path)
        except TypeError as path_resolve_bad_os_err:
            self.ClamLog.warning('__resolve_path: Failed to resolve {}.'.format(path))
            self.ClamLog.info('__resolve_path: TIP: Probably wrong OS type detected.')
            self.ClamLog.debug('__resolve_path: TypeError occurred, log: {}'.format(str(path_resolve_bad_os_err.args)))
            self.ClamLog.info('__resolve_path: Trying to run anyway...')
            return str(path)
        finally:
            self.ClamLog.debug('__resolve_path: Path converted. Return {}'.format(str(path.expanduser().resolve())))
            return str(path.expanduser().resolve())
