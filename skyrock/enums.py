from enumfields import Enum

class ScheduleType(Enum):
    PHASE1 = 'phase1'

class Role(Enum):
    STUDENT = 'student'
    TEACHER = 'teacher'
    PARENT = 'parent'
    ADMIN = 'admin'
    DEVELOPER = 'developer'

class Attendance_status(Enum):
    PRESENT = 'present'
    NOT_PRESENT = 'not-present'
    EXCUSED = 'excused'

class Location(Enum):
    TIANMU = 'tianmu'
    DAZHI = 'dazhi'
    NONE = 'none'

class Clubs(Enum):
    YOUNG_INVENTORS = 'Young Inventors'
    MACHINE_MAKERS = 'Machine Makers'
    CODE_WIZARDS = 'Code Wizards'
    GAME_CREATORS = 'Game Creators'
    FASHION_ENGINEERS = 'Fashion Engineers'
    MUSIC_INNOVATORS = 'Music Innovators'
    NANO = 'Nano'
    MEGA = 'Mega'
    NONE = 'None'
    


# class pathways(Enum):
#     PRESENT = 'present'
#     NOT_PRESENT = 'not-present'
#     EXCUSED = 'excused'
    

