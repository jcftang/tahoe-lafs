[ ]  1 update doc files: `<../relnotes.txt>`_, `<../CREDITS>`_, `<known_issues.rst>`_, `<../NEWS.rst>`_. Add release name and date to top-most item in NEWS.

[ ]  2 change `<quickstart.rst>`_ to point to just the current allmydata-tahoe-X.Y.Z.zip source code file, or else to point to a directory which contains only allmydata-tahoe-X.Y.Z.* source code files

[ ]  3 darcs pull

[ ]  4 make tag

[ ]  5 build locally to make sure the release is reporting itself as the intended version

[ ]  6 make sure buildbot is green

[ ]  7 make sure other people aren't committing at that moment

[ ]  8 push tag along with some other documentation-only patch (typically to relnotes.txt) to trigger buildslaves

[ ]  9 make sure buildbot is green

[ ] 10 make sure debs got built and uploaded properly

[ ] 11 make sure a sumo sdist tarball got built and uploaded properly

[ ] 12 symlink the release tarball on tahoe-lafs.org: /var/www/source/tahoe-lafs/releases/

[ ] 13 update Wiki: front page news, news, old news, parade of release notes

[ ] 14 send out relnotes.txt: [ ] tahoe-announce@tahoe-lafs.org, [ ] tahoe-dev@tahoe-lafs.org, [ ] p2p-hackers@lists.zooko.com, [ ] lwn@lwn.net, [ ] cap-talk@mail.eros-os.org, [ ] cryptography@metzdown.com, [ ] cryptography@randombit.net, [ ] twisted-python@twistedmatrix.com, [ ] owncloud@kde.org, [ ] liberationtech@lists.stanford.edu, [ ] the "decentralization" group on groups.yahoo.com, [ ] pycrypto mailing list, -> fuse-devel@lists.sourceforge.net, -> fuse-sshfs@lists.sourceforge.net, [ ] duplicity-talk@nongnu.org, [ ] news@phoronix.com, [ ] python-list@python.org, -> cygwin@cygwin.com, [ ] The Boulder Linux Users' Group, [ ] The Boulder Hackerspace mailing list, [ ] cryptopp-users@googlegroups.com, [ ] tiddlywiki, [ ] hdfs-dev@hadoop.apache.org, [ ] bzr, [ ] mercurial, [ ] http://listcultures.org/pipermail/p2presearch_listcultures.org/ , deltacloud, libcloud, [ ] swift@lists.launchpad.net, cleversafe.org, [ ] stephen@fosketts.net, [ ] Chris Mellor of The Register, [ ] nosql@mypopescu.com

[ ] 15 update `<https://tahoe-lafs.org/hacktahoelafs/>`_

[ ] 16 make an "announcement of new release" on freshmeat

[ ] 17 upload to pypi with "python ./setup.py sdist upload register"

[ ] 18 make an "announcement of new release" on launchpad

[ ] 19 close the Milestone on the trac Roadmap
