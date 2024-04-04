import random


class HandleManager:
    numbers = numbers = list(range(1, 0x100000 + 1))
    used = []
    handle_infos = {}

    @classmethod
    def create_handle(cls):
        if not cls.numbers:
            return None
        chosen = random.choice(cls.numbers)
        cls.numbers.remove(chosen)
        cls.used.append(chosen)
        return chosen

    @classmethod
    def close_handle(cls, handle):
        if handle in cls.used:
            cls.used.remove(handle)
            cls.numbers.append(handle)
        else:
            print(f"handle {handle} was not used or does not exist.")

    @classmethod
    def get_info(cls, handle):
        return cls.handle_infos[handle]

    @classmethod
    def set_info(cls, handle, info):
        cls.handle_infos[handle] = info
