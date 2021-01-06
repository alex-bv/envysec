import datetime
import logging
import os
import pathlib
import sqlite3
import shlex


class DBManager():
    """ Used to control databases.

    Available methods:
        public: execute_db
        private: __connect_db, __close_db, __create_db

    Dependencies:
        built-in: logging, os, pathlib, sqlite3, shlex
        3-d party: -
    """

    def __init__(self, logging_level = 30, database = './modules/exclude.db'):
        """ Manage SQL database.

        'database' - path to database with exclusions.
        'logging_level' - verbosity of logging:
            0 - debug,
            30 - warnings,
            50 - critical.
            See 'logging' docs;
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format=f"%(asctime)s - [%(levelname)s] - %(name)s - (%(filename)s).%(funcName)s(%(lineno)d) - %(message)s",
                            datefmt='%d.%m.%Y %H:%M:%S')

        self.DBManager = logging.getLogger('DBManager')
        self.DBManager.debug('Initializing class...')

        self.DBManager.debug('Checking database existence...')
        self.database = pathlib.Path('.').resolve().joinpath(database)
        if self.database.exists() is True:
            self.DBManager.info('Database found.')
        elif self.__create_db() is False:
            self.DBManager.critical('Database path {} not found!'.format(self.database))
            raise FileNotFoundError('Database path {} not found!'.format(self.database))
        else:
            self.DBManager.error('Database path {} not found!'.format(self.database))
            self.DBManager.info('{} database created.'.format(self.database))

        self.DBManager.debug('Class initialized.')


    def __connect_db(self) -> bool:
        """ Connect to secEnvyronment database.
        To close connection use '__close_db';

        Default database filename is 'exclude.db' (./modules/exclude.db).
        Default exclude.db have table 'Exclusion', 'Statistic'.

        Note: this method cant be used to initialize database.
        """

        self.DBManager.info('Connecting to Exclude database...')
        self.DBManager.debug('Trying {} ...'.format(str(self.database)))

        if self.database.exists() is True:
            try:
                self.exclude_connect = sqlite3.connect(str(self.database))
                self.dbcursor = self.exclude_connect.cursor()

            except sqlite3.NotSupportedError as sql_bad_db_err:
                self.DBManager.warning('Wrong database type detected!')
                self.DBManager.debug('Database error log: {}'.format(str(sql_bad_db_err.args)))
                return False
            except sqlite3.DataError as sql_data_err:
                self.DBManager.warning('Database error occurred!')
                self.DBManager.debug('Database error log: {}'.format(str(sql_data_err.args)))
                return False
            except sqlite3.IntegrityError as sql_broken_db_err:
                self.DBManager.warning('Database integrity compromised.')
                self.DBManager.debug('Database error log: {}'.format(str(sql_broken_db_err.args)))
                return False
            except sqlite3.OperationalError as sql_operation_err:
                self.DBManager.warning('Database integrity compromised.')
                self.DBManager.debug('Database error log: {}'.format(str(sql_operation_err.args)))
                return False
            except PermissionError as permissions_denied:
                self.DBManager.warning('Permissions denied.')
                self.DBManager.debug('Database error log: {}'.format(str(permissions_denied.args)))
                return False
        else:

            self.__create_db()

            self.DBManager.warning('Database does not exist or permissions denied.')
            self.DBManager.debug('Can\'t connect to {}'.format(str(self.database)))
            return False

        self.DBManager.debug('Connected.')
        return True

    def __close_db(self) -> bool:
        """ Close connection to secEnvyronment database.
        To open connection use __connect_db;

        Default database filename is 'exclude.db' (./modules/exclude.db).
        Default exclude.db have table 'Exclusion', 'Statistic'.
        """

        self.DBManager.info('Closing Database connection...')

        try:
            self.DBManager.debug('Commiting...')
            self.exclude_connect.commit()
            self.DBManager.debug('Closing database...')
            self.dbcursor.close()
        except sqlite3.ProgrammingError as sql_programming_err:
            self.DBManager.warning('Programming error occurred!')
            self.DBManager.debug('Database error log: {}'.format(str(sql_programming_err.args)))
            return False
        except sqlite3.OperationalError as sql_bad_operation_err:
            self.DBManager.warning('Operational error occurred!')
            self.DBManager.debug('Database error log: {}'.format(str(sql_bad_operation_err.args)))
            return False

        self.DBManager.debug('Complete.')
        return True


    def __create_db(self, structure = {'Exclusion': ['Path', 'Date'], 'Statistic': ['Found', 'Date', 'TotalReports']}) -> bool:
        """ Create database.

        Used to create sqlite database.

        Create database in 'self.database' path.
        The database structure is defined in 'structure'.
        Default structure is consist of 2 tables:
        'Exclusion', used to control user exclude list,
        'Statistic', used to store scan statistic.

        Table 'Exclusion' have 2 columns:
        'Path' - is a path to file or dir to be excluded from scan,
        'Date' - is a date exclusion were added.

        Table 'Statistic' have 3 columns:
        'Found' - is a path to file or dir to infected file,
        'Date' - is a date infected file were found,
        'TotalReports' - is a number of infected file reports.

        If database is already exists, return False.
        If database created but may not be connected, return False.
        If database created and available to connection, return True.
        """

        self.DBManager.debug('Initialize __create_db...')

        def __create_command(structure: dict) -> str:
            """ Create SQL command to create structure.

            Structure is a dict, where:
            Keys are table names to be created,
            Values are columns to be created.

            Return command string to be sent to SQL exec.
            """

            self.DBManager.debug('Creating command, received structure: {}'.format(structure))
            for table in structure:
                command = 'CREATE TABLE IF NOT EXISTS'
                command += ' {} ('.format(shlex.quote(table))
                for column in structure[table]:
                    command += '{} VARCHAR (255) NOT NULL, '.format(shlex.quote(column))
                command += 'PRIMARY KEY ({})); '.format(structure[table][0])
                self.DBManager.debug('Created command: {}'.format(shlex.quote(command)))
                yield command

        self.DBManager.debug('Checking database existence.')
        if os.path.exists(self.database) is False:
            self.DBManager.info('Database is not found!')
            self.DBManager.debug('Trying to create database:')
            self.DBManager.debug('Connecting...')
            try:
                db_connection = sqlite3.connect(self.database)
            except FileExistsError:
                self.DBManager.warning('Filename {} already taken.'.format(self.database))
                return False
            except PermissionError:
                self.DBManager.warning('Can\'t create database, permissions denied.')
                return False

            self.DBManager.debug('Init cursor...')
            db_cursor = db_connection.cursor()
            self.DBManager.debug('Creating table...')
            try:
                for command in __create_command(structure):
                    db_cursor.execute(command) # SQL, insecure
                    db_connection.commit()
                    db_connection.close()
            except sqlite3.ProgrammingError: #?
                self.DBManager.warning('Programming error, trying to continue...')
            else:
                self.DBManager.debug('Done without errors.')
        else:
            self.DBManager.info('Database is already exists.')
            return False

        self.DBManager.debug('Checking database.')
        if self.__connect_db() is True:
            self.DBManager.debug('Database check passed witout errors, closing.')
            self.__close_db()
            self.DBManager.debug('Database closed.')
        else:
            self.DBManager.error('Cannot connect database!')
            return False

        self.DBManager.debug('Database created.')
        return True

    def execute_db(self, command: str, values: tuple = None) -> bool:
        """ Execute SQL command.

        Default database structure is consist of 2 tables:
        'Exclusion', used to control user exclude list,
        'Statistic', used to store scan statistic.

        By default, table 'Exclusion' have 2 columns:
        'Path' - is a path to file or dir to be excluded from scan,
        'Date' - is a date exclusion were added.

        By default, table 'Statistic' have 3 columns:
        'Found' - is a path to file or dir to infected file,
        'Date' - is a date infected file were found,
        'TotalReports' - is a number of infected file reports.
        """

        self.DBManager.info('Executing...')
        if self.__connect_db() is True:
            try:
                self.DBManager.info('Adding exception to database.') # TODO: make it yield output
                self.DBManager.debug('Verifying path...')

                output = []
                if values != None and type(values) == tuple:
                    self.DBManager.debug('Executing {} with arguments {}'.format(command, values))
                    for out in self.dbcursor.execute(command, values): # SQL
                        output += out
                    self.DBManager.debug('Executed;')
                elif values == None:
                    self.DBManager.debug('Executing {} with no arguments.'.format(command))
                    for out in self.dbcursor.execute(command): # SQL
                        self.DBManager.debug('Received: {};'.format(out))
                        output += out
                    self.DBManager.debug('Executed;')
                elif type(values) != tuple:
                    self.DBManager.critical('Cant execute command!')
                    self.DBManager.error('Bad SQL values received: {}, turple should be received!'.format(values))
                    raise TypeError('Bad SQL command arguments type!')
                else:
                    self.DBManager.error('Error occured, wont execute SQL command.')
                    self.DBManager.debug('Bad SQL command: {}.'.format(command))

            except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
                self.DBManager.warning('Failed execute SQL command.')
                self.DBManager.debug('Database error log: {}'.format(str(sql_err.args)))
                if self.__close_db() is True:
                    self.DBManager.debug('Database closed secessfully.')
                    return []
                else:
                    raise
            finally:
                self.DBManager.debug('Database management complete.')
                if self.__close_db() is True:
                    return output
                else:
                    return []
        else:
            return []



class ExcludeDB(DBManager):
    """ Used to manage 'Exclusion' table in database.

    Available methods:
        public: add_exception, remove_exception, get_exceptions
        private: -

    Dependencies:
        built-in: datetime, logging, os, pathlib, sqlite3
        3-d party: -
    """

    def __init__(self, logging_level = 30, database = './modules/exclude.db'):
        """ Manage exclude list.
        Exclude list is located in './modules/exclude.db', in table 'Exclusion'.
        'Path' is a primary key in 'Exclusion' table.

        'database' - path to database with exclusions.
        'logging_level' - verbosity of logging:
            0 - debug,
            30 - warnings,
            50 - critical.
            See 'logging' docs;
        """

        DBManager.__init__(self, logging_level, database)

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format=f"%(asctime)s - [%(levelname)s] - %(name)s - (%(filename)s).%(funcName)s(%(lineno)d) - %(message)s",
                            datefmt='%d.%m.%Y %H:%M:%S')

        self.ExcludeDB = logging.getLogger('ExcludeDB')
        self.ExcludeDB.debug('Initializing class...')

        self.ExcludeDB.debug('Checking database existence...')
        self.database = pathlib.Path('.').resolve().joinpath(database)
        if self.database.exists() is True:
            self.ExcludeDB.info('database found.')
        elif DBManager.__create_db(self) is False:
            self.ExcludeDB.critical('database path {} not found!'.format(self.database))
            raise FileNotFoundError('Database path {} not found!'.format(self.database))
        else:
            self.ExcludeDB.error('database path {} not found!'.format(self.database))
            self.ExcludeDB.info('{} database created.'.format(self.database))

        self.ExcludeDB.debug('Class initialized.')


    def add_exception(self, path: str) -> bool:
        """ Add path to exclude list.
        Exclude list is located in './modules/exclude.db', in table 'Exclusion'.

        'path' - is a path to file or folder to be added to exclude list.

        Used to connect and add path to 'exclude.db'.
        If 'Path' added, date will be automatically appended into table.
        """

        self.ExcludeDB.info('Adding exception...')
        path = self.__resolve_path(path)

        try:
            self.ExcludeDB.info('Adding exception to database.')
            self.ExcludeDB.debug('Verifying path...')
            if os.path.exists(path) is True:
                self.ExcludeDB.debug('Add exception: {}'.format(path))
                self.execute_db(command = "INSERT INTO Exclusion VALUES (?, ?)", values = (path, datetime.datetime.now(),)) # SQL
            else:
                self.ExcludeDB.warning('{} does not exists;'.format(path))
                return False
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('Failed execute SQL command.')
            self.ExcludeDB.debug('Database error log: {}'.format(str(sql_err.args)))
            return False
        finally:
            self.ExcludeDB.debug('Database management complete.')
            return True

    def remove_exception(self, path: str) -> bool:
        """ Remove path from exclude list.
        Exclude list is located in './modules/exclude.db', in table 'Exclusion'.

        'path' - is a path to file or folder to be removed from exclude list.

        Used to connect and remove path from 'exclude.db'.
        'Path' is a primary key in 'Exclusion' table.
        """

        self.ExcludeDB.info('Removing exception...')
        path = self.__resolve_path(path)

        try:
            self.ExcludeDB.info('Removing {} from database.'.format(path))
            self.ExcludeDB.debug('Trying to remove exception: {}'.format(path))
            self.execute_db("DELETE FROM Exclusion WHERE Path=(?);", values = (path,)) # SQL
            self.ExcludeDB.info('{} successfully removed.'.format(path))
        except(sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('Failed execute SQL command.')
            self.ExcludeDB.debug('Database error log: {}'.format(str(sql_err.args)))
            return False
        finally:
            self.ExcludeDB.debug('Database management complete.')
            return True

    def get_exceptions(self) -> list:
        """ Get all items in exclude list.

        Used to connect and get list from 'exclude.db'.

        Executing 'for ... in ... SELECT * FROM Exclusion' will return tuple;
        By design, only 1 object in tuple will be counted, other will be skipped.
        Yielding first item in a tuple 'item[0]'.

        Return None if database error occurred.
        """

        self.ExcludeDB.info('Getting exceptions...')
        exclude_list = {}

        try:
            self.ExcludeDB.debug('Getting exclude list;')
            exclude_list = dict(zip(self.execute_db(command = "SELECT Path FROM Exclusion;"), self.execute_db(command = "SELECT Date FROM Exclusion;"))) # SQL
            self.ExcludeDB.debug('Total exclude list: {}'.format(exclude_list))
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('Failed execute SQL command.')
            self.ExcludeDB.debug('Database error log: {}'.format(str(sql_err.args)))
            return {}
        finally:
            self.ExcludeDB.debug('Database management complete.')
            return exclude_list

    def __resolve_path(self, path: str) -> str:
        """ Resolve path string to absolute path.

        'path' - is a path to file or dir (absolute or symlink) to be resolved.

        Used to resolve symlinks and return absolute path.
        """

        self.DBManager.info('Starting path resolver.')
        self.DBManager.debug('Resolving {}...'.format(path))

        try:
            path = pathlib.Path(path)
        except NotImplementedError as path_resolve_bad_python_err:
            self.DBManager.warning('Failed to resolve {}.'.format(path))
            self.DBManager.info('TIP: Probably OS is not supported.')
            self.DBManager.debug('NotImplementedError occurred, log: {}'.format(str(path_resolve_bad_python_err.args)))
            self.DBManager.info('Trying to run anyway...')
            return str(path)
        except TypeError as path_resolve_bad_os_err:
            self.DBManager.warning('Failed to resolve {}.'.format(path))
            self.DBManager.info('TIP: Probably wrong OS type detected.')
            self.DBManager.debug('TypeError occurred, log: {}'.format(str(path_resolve_bad_os_err.args)))
            self.DBManager.info('Trying to run anyway...')
            return str(path)
        finally:
            self.DBManager.debug('Path converted. Return {}'.format(str(path.expanduser().resolve())))
            return str(path.expanduser().resolve())
