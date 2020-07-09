
class PerFileProgressCallbacks:
    def __init__(self):
        self.clear_file_vars()
        self.total_sectors_to_be_written = 0
        self.total_sectors_being_written = 0
        self.total_sectors_written = 0
        self.filenames_collected_at_start = []
        self.filenames_collected_in_progress = []
        self.filenames_collected_at_end = []

    def clear_file_vars(self):
        self.file_name_to_be_written = None
        self.file_sectors_to_be_written = 0
        self.file_name_being_written = None
        self.file_sectors_being_written = 0
        self.file_name_written = None
        self.file_sectors_written = None
        self.result = None
        self.last_being_written = 0

    def register_callbacks(self, firehose):
        firehose.register_file_progress_callbacks(self.handle_start_file_sectors,
                                                  self.handle_sent_file_sectors,
                                                  self.handle_finished_sectors_from_file)

    def handle_start_file_sectors(self, fname, sectors_to_be_written):
        self.file_name_to_be_written = fname
        self.filenames_collected_at_start += [fname]
        self.file_sectors_to_be_written = sectors_to_be_written
        self.total_sectors_to_be_written += sectors_to_be_written
        self.last_being_written = 0

    def handle_sent_file_sectors(self, fname, file_sectors_written):
        if not fname in self.filenames_collected_in_progress:
            self.filenames_collected_in_progress += [fname]
        self.file_name_being_written = fname
        self.file_sectors_being_written = file_sectors_written
        change = file_sectors_written - self.last_being_written
        self.total_sectors_being_written += change
        self.last_being_written = file_sectors_written

    def handle_finished_sectors_from_file(self, fname, result, sectors_written):
        self.file_name_written = fname
        self.filenames_collected_at_end += [fname]
        self.result = result
        self.file_sectors_written = sectors_written
        self.total_sectors_written += sectors_written
        self.last_being_written = 0

    def check_file_result(self, fname, sectors):
        assert(self.file_name_to_be_written == fname)
        if (sectors > 0):
            assert(self.file_name_being_written == fname)
        assert(self.file_name_written == fname)
        assert(self.file_sectors_to_be_written == sectors)
        assert(self.file_sectors_being_written == sectors)
        assert(self.file_sectors_written == sectors)
        assert(self.result == 0)

    def check_totals(self, total_sectors):
        assert(self.total_sectors_to_be_written == total_sectors)
        assert(self.total_sectors_written == total_sectors)
        assert(self.total_sectors_being_written == total_sectors)


class PercentProgressCallbacks:
    def __init__(self):
        self.called_values = []

    def register_callbacks(self, firehose, image_size):
        firehose.register_percent_progress_callbacks(self.handle_percent, image_size)

    def handle_percent(self, percent):
        self.called_values += [percent]

