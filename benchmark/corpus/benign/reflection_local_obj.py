def dispatch(handler, name):
    method = name
    return getattr(handler, method)()
