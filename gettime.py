from datetime import datetime
import time
def nowtime():

    fmt1 = "%Y-%m-%d"
    fmt2 = "%Y-%m-%d_%H_%M_%S"
    dt = datetime.now()
    pathname = dt.strftime(fmt1)
    now_time = dt.strftime(fmt2)
    # print(new_date,new_date_second)
    return pathname,now_time