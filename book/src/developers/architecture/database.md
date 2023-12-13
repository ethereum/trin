# Database

The database related code is located in `./portalnet/storage.rs`.

There are three main database kinds:

| DB Name |Kind|Location| Purpose        |Keys| Values                                   |
|---------|-|-|----------------|-|------------------------------------------|
| Main    |SQLite|Disk| Data store     |Content ID| Content key, content value, content size |
| Memory  |HashMap|Memory| Kademlia cache |Content key| Content data bytes                       |

## Main content database

This is an SQLite database that stores content data. For a piece of content, this includes
the content ID, content key, content value and the size of the content. It makes assessing the size of
the database quicker by avoiding the need to repeatedly compute the size of each content.

## Memory content database

This uses is an in-memory hashmap to keep content that may not be required for long term
storage. An overlay service uses this database when receiving data from a peer as
part of Kademlia-related actions. If required, data is later moved to disk in the
main content database.
