
class LookupObject(object):
    def __init__(self, objects, master_id, io):
        self.object = None
        for gbr_object in objects:
            if gbr_object.object_id == master_id:
                self.object = gbr_object
                break
