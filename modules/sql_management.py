import logging
import os
import pathlib
import sqlite3


class ExcludeDB():
    """ Used to control exceptions.
    Store and get exception list in SQLite database.

    Available methods:
        public: add_exception, remove_exception, get_exception
        private: __connect_db, __close_db, __resolve_path, __create_db

    Dependencies:
        built-in: logging, os, pathlib, sqlite3
        3-d party: -
    """

    def __init__(self, logging_level = 30, database = './modules/exclude.db'):
        """  Manage SQL database.

        'database' - path to database with exclusions.
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

        self.ExcludeDB = logging.getLogger('ExcludeDB')
        self.ExcludeDB.debug('__init__: Initializing class...')

        self.ExcludeDB.debug('__init__: Checking database existence...')
        self.database = pathlib.Path('.').resolve().joinpath(database)
        if self.database.exists() is True:
            self.ExcludeDB.info('__init__: database found.')
        elif self.__create_db() is False:
            self.ExcludeDB.critical('__init__: database path {} not found!'.format(self.database))
            raise FileNotFoundError('Database path {} not found!'.format(self.database))
        else:
            self.ExcludeDB.error('__init__: database path {} not found!'.format(self.database))
            self.ExcludeDB.info('__init__: {} database created.'.format(self.database))

        self.ExcludeDB.debug('__init__: Class initialized.')


    def __connect_db(self) -> bool:
        """ Connect to ClamAV exclude database.
        To close connection use '__close_db';

        Used to control ClamAV scan output;

        Default exclude.db have one single table 'exclude'.
        Exclude database filename is 'exclide.db' (secEnvyronment/modules/exclude.db).
        """

        self.ExcludeDB.info('__connect_db: Connecting to Exclude database...')
        self.ExcludeDB.debug('__connect_db: Trying {} ...'.format(str(self.database)))

        if self.database.exists() is True:
            try:
                self.__exclude_connect = sqlite3.connect(str(self.database))
                self.__dbcursor = self.__exclude_connect.cursor()
            except sqlite3.NotSupportedError as sql_bad_db_err:
                self.ExcludeDB.warning('__connect_db: Wrong database type detected!')
                self.ExcludeDB.debug('__connect_db: Database error log: {}'.format(str(sql_bad_db_err.args)))
                return False
            except sqlite3.DataError as sql_data_err:
                self.ExcludeDB.warning('__connect_db: Database error occurred!')
                self.ExcludeDB.debug('__connect_db: Database error log: {}'.format(str(sql_data_err.args)))
                return False
            except sqlite3.IntegrityError as sql_broken_db_err:
                self.ExcludeDB.warning('__connect_db: Database integrity compromised.')
                self.ExcludeDB.debug('__connect_db: Database error log: {}'.format(str(sql_broken_db_err.args)))
                return False
        else:
            self.ExcludeDB.warning('__connect_db: Database does not exist or permissions denied.')
            self.ExcludeDB.debug('__connect_db: Can\'t connect to {}'.format(str(self.database)))
            return False

        self.ExcludeDB.debug('__connect_db: Connected.')
        return True

    def __close_db(self) -> bool:
        """ Close connection to ClamAV exclude database.
        To open connection use __connect_db;

        Used to control ClamAV scan output;

        Default exclude.db have to have single table 'exclude'.
        Exclude database filename is 'exclide.db' (secEnvyronment/modules/exclude.db).
        """

        self.ExcludeDB.info('__close_db: Closing Database connection...')

        try:
            self.ExcludeDB.debug('__close_db: Commiting...')
            self.__exclude_connect.commit()
            self.ExcludeDB.debug('__close_db: Closing database...')
            self.__dbcursor.close()
        except sqlite3.ProgrammingError as sql_programming_err:
            self.ExcludeDB.warning('__close_db: Programming error occurred!')
            self.ExcludeDB.debug('__close_db: Database error log: {}'.format(str(sql_programming_err.args)))
            return False
        except sqlite3.OperationalError as sql_bad_operation_err:
            self.ExcludeDB.warning('__close_db: Operational error occurred!')
            self.ExcludeDB.debug('__close_db: Database error log: {}'.format(str(sql_bad_operation_err.args)))
            return False

        self.ExcludeDB.debug('__close_db: Complete.')
        return True

    def __create_db(self):
        """ Create database.

        Used to create sqlite database.

        Create database in 'self.database' path.
        The database will contain the only table: 'exclude' with single column: 'path'.

        If database is already exists, return False.
        If database created but may not be connected, return False.
        If database created and available to connection, return True.
        """

        self.ExcludeDB.debug('__create_db: Initialize __create_db...')

        self.ExcludeDB.debug('__create_db: Checking database existence.')
        if os.path.exists(self.database) is False:
            self.ExcludeDB.warning('__create_db: Database is not found!')
            self.ExcludeDB.debug('__create_db: Trying to create database:')

            self.ExcludeDB.debug('__create_db: Connecting...')
            db_connector = sqlite3.connect(self.database)
            self.ExcludeDB.debug('__create_db: Init cursor...')
            db_cursor = db_connector.cursor()
            self.ExcludeDB.debug('__create_db: Creating table...')
            db_cursor.execute("CREATE TABLE IF NOT EXISTS exclude (path VARCHAR (255) NOT NULL, PRIMARY KEY (path))")
            self.ExcludeDB.debug('__create_db: Done without errors.')
        else:
            self.ExcludeDB.info('__create_db: Database is already exists.')
            return False

        self.ExcludeDB.debug('__create_db: Checking database.')
        if self.__connect_db() is True:
            self.ExcludeDB.debug('__create_db: Database check passed witout errors, closing.')
            self.__close_db()
            self.ExcludeDB.debug('__create_db: Database closed.')
        else:
            self.ExcludeDB.error('__create_db: Cannot connect database!')
            return False

        self.ExcludeDB.debug('__create_db: Database created.')
        return True


    def add_exception(self, path: str) -> bool:
        """ Add path to exclude list.

        'path' - is a (string) path to file/folder.

        Used to connect and add path to 'exclude.db'.
        """

        self.ExcludeDB.info('add_exception: Adding exception...')
        self.__connect_db()
        path = self.__resolve_path(path)

        try:
            self.ExcludeDB.info('add_exception: Adding exclude to database.')
            self.ExcludeDB.debug('add_exception: Verifying path...')
            if os.path.exists(path) is True:
                self.ExcludeDB.debug('add_exception: Add exclude: {}'.format(path))
                self.__dbcursor.execute("INSERT INTO exclude(path) VALUES (?)", (path,))
            else:
                self.ExcludeDB.warning('add_exception: {} does not exist;'.format(path))
                self.__close_db()
                return False
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('add_exception: Failed execute SQL command.')
            self.ExcludeDB.debug('add_exception: Database error log: {}'.format(str(sql_err.args)))
            self.__close_db()
            return False
        finally:
            self.ExcludeDB.debug('add_exception: Database management complete.')
            self.__close_db()
            return True

    def remove_exception(self, path: str) -> bool:
        """ Remove path from exclude list.

        'path' - is a (string) path to file/folder.

        Used to connect and remove path from 'exclude.db'.
        """

        self.ExcludeDB.info('remove_exception: Removing exception...')
        self.__connect_db()
        path = self.__resolve_path(path)

        try:
            self.ExcludeDB.info('remove_exception: Removing {} from database.'.format(path))
            self.ExcludeDB.debug('remove_exception: Trying to remove exclude: {}'.format(path))

            for out in self.__dbcursor.execute("SELECT 1 FROM exclude WHERE path=(?)", (path,)):
                if out == (1,):
                    self.__dbcursor.execute("DELETE FROM exclude WHERE path =(?)", (path,))
                    self.ExcludeDB.info('remove_exception: {} successfully removed.'.format(path))
                else:
                    self.ExcludeDB.warning('remove_exception: Failed to remove {} from database.'.format(path))
                    self.ExcludeDB.info('remove_exception: {} not in database.'.format(path))
                    self.__close_db()
                    return False
        except(sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('remove_exception: Failed execute SQL command.')
            self.ExcludeDB.debug('remove_exception: Database error log: {}'.format(str(sql_err.args)))
            self.__close_db()
            return False
        finally:
            self.ExcludeDB.debug('remove_exception: Database management complete.')
            self.__close_db()
            return True

    def get_exception(self) -> list:
        """ Get all items in exclude list.

        Used to connect and get list from 'exclude.db'.

        Executing 'for ... in ... SELECT * FROM exclude' will return tuple;
        By design, only 1 object in tuple will be counted, other will be skipped.
        Yielding first item in a tuple 'item[0]'.

        Return None if database error occurred.
        """

        self.ExcludeDB.info('get_exception: Getting exceptions...')
        self.__connect_db()
        exclude_list = list()

        try:
            self.ExcludeDB.debug('get_exception: Getting exclude list;')
            for row in self.__dbcursor.execute("SELECT * FROM exclude;"):
                self.ExcludeDB.debug('get_exception: In exclude: {}'.format(str(row[0])))
                self.ExcludeDB.debug('get_exception: Raw exception line: {}'.format(str(row)))
                exclude_list += [row[0]]
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as sql_err:
            self.ExcludeDB.warning('get_exception: Failed execute SQL command.')
            self.ExcludeDB.debug('get_exception: Database error log: {}'.format(str(sql_err.args)))
            self.__close_db()
            return []
        finally:
            self.ExcludeDB.debug('get_exception: Database management complete.')
            self.__close_db()
            if exclude_list != []:
                return exclude_list
            else:
                return []


    def __resolve_path(self, path: str) -> str:
        """ Resolve path string to absolute path.

        'path' - is a (string) path to file or dir.

        Used to resolve symlinks and return absolute path.
        """

        self.ExcludeDB.info('__resolve_path: Starting path resolver.')
        self.ExcludeDB.debug('__resolve_path: Resolving {}...'.format(path))

        try:
            path = pathlib.Path(path)
        except NotImplementedError as path_resolve_bad_python_err:
            self.ExcludeDB.warning('__resolve_path: Failed to resolve {}.'.format(path))
            self.ExcludeDB.info('__resolve_path: TIP: Probably OS is not supported.')
            self.ExcludeDB.debug('__resolve_path: NotImplementedError occurred, log: {}'.format(str(path_resolve_bad_python_err.args)))
            self.ExcludeDB.info('__resolve_path: Trying to run anyway...')
            return str(path)
        except TypeError as path_resolve_bad_os_err:
            self.ExcludeDB.warning('__resolve_path: Failed to resolve {}.'.format(path))
            self.ExcludeDB.info('__resolve_path: TIP: Probably wrong OS type detected.')
            self.ExcludeDB.debug('__resolve_path: TypeError occurred, log: {}'.format(str(path_resolve_bad_os_err.args)))
            self.ExcludeDB.info('__resolve_path: Trying to run anyway...')
            return str(path)
        finally:
            self.ExcludeDB.debug('__resolve_path: Path converted. Return {}'.format(str(path.expanduser().resolve())))
            return str(path.expanduser().resolve())
