import logging
from typing import Iterator

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.locate.everything import EverythingDBParser
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export, Plugin

EverythingRecord = TargetRecordDescriptor(
    "windows/everything/everything_record",
    [
        ("string", "path"),
        ("filesize", "size"),
        ("datetime", "date_created"),
        ("datetime", "date_modified"),
        ("datetime", "date_accessed"),
        ("uint32", "attributes"),
        ("string", "record_type"),
        ("string", "source"),
    ],
)
logger = logging.getLogger(__name__)


class EverythingPlugin(Plugin):
    __namespace__ = "everything"

    PATH_GLOBS = [
        "C:\\Program Files\\Everything\\Everything*.db",
        "C:\\Program Files (x86)\\Everything\\Everything*.db",
    ]
    USER_PATH = "AppData\\Local\\Everything\\Everything*.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.configs = []
        for path_option in self.PATH_GLOBS:
            for path in self.target.fs.path().glob(path_option):
                if path.exists():
                    self.configs.append(path)

        for path in self.find_user_files():
            self.configs.append(path)

    def find_user_files(self) -> Iterator[TargetPath]:
        for user_details in self.target.user_details.all_with_home():
            for db in user_details.home_path.glob(self.USER_PATH):
                if db.exists():
                    yield db

    def check_compatible(self) -> None:
        if not self.configs:
            raise UnsupportedPluginError("No everything.db files found")

    @export(record=EverythingRecord)
    def locate(self) -> Iterator[EverythingRecord]:
        """Yield file and directory names from everything.db file."""
        for path in self.configs:
            try:
                everything_fh = self.target.fs.path(path).open()
                everything_file = EverythingDBParser(everything_fh)

                for item in everything_file:
                    yield EverythingRecord(
                        path=item.file_path,
                        size=item.size,
                        date_created=item.date_created,
                        date_modified=item.date_modified,
                        date_accessed=item.date_accessed,
                        attributes=item.attributes,
                        record_type=item.file_type,
                        source=path,
                        _target=self.target,
                    )
            except (NotImplementedError, ValueError) as e:
                logger.warning("Invalid EverythingDB %s: %s", path, e)
                # TODO - Remove after testing
                raise e
