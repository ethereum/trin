# Database

The database related code is located in `./portalnet/storage.rs`.

There are three main database kinds:

|DB Name|Kind|Location|Purpose|Keys|Values|
|-|-|-|-|-|-|
|Main|RocksDB|Disk|Data store|Content ID|Content data bytes|
|Memory|HashMap|Memory|Kademlia cache|Content key|Content data bytes|
|Meta|SQLite|Disk|Manage DB size|Content ID|Content key, content size|

## Main content database

This is a persistent file-based database that uses RocksDB.
It is also called the "radius" database because content management rules are based on
the radius of content (specifically the content distance to the node ID).

## Memory content database

This uses is an in-memory hashmap to keep content that may not be required for long term
storage. An overlay service uses this database when receiving data from a peer as
part of Kademlia-related actions. If required, data is later moved to disk in the
main content database.

## Meta database

This is an SQLite database that stores metadata. For a piece of content, this includes
the content ID, content key and the size of the content. It makes assessing the size of
the main database quicker by avoiding the need to repeatedly compute the size of each content.

Database updates occur in tandum with the main database, where if an operation in one database
fails, the other can revert the operation to remain synced.
