def call(obj, name):
    return getattr(obj, name)()
