import webbrowser


def get_search_url(event_id, source):

    query = f"{source} Event ID {event_id}"

    return (
        "https://www.google.com/search?q="
        + query.replace(" ", "+")
    )


def lookup_event(event_id, source):

    return {
        "search_url": get_search_url(
            event_id,
            source
        )
    }