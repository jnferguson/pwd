This was intended as a basic proof of concept that some of the web 2.0 ideals are not entirely up to snuff, in particular that we transfer plain-text passwords across the network so that the server can hash them and compare a hash to a hash and inhibit the risk of data loss in the event of a SQL injection based data compromise. My sentiment has been that this fails to reflect modern network architecture, that the plain-text credentials are passed along any number of systems that terminate SSL and rewrap them and so on all of which can be compromised. There is a true risk reduction in the sense that you only receive the passwords for users that login, but my point was simply that there is another different way to handle the problem using best design practices from the 90s where both ends of the connection verify that each end has access to a shared secret without ever divulging what that secret is.

Furthermore, as a side-channel dump, the creation of a session key on the basis of this shared secret as I did with the ECC keypair allows for the creation of application layer data encryption, which almost entirely eliminates the loss of security from the compromise of a cookie-- the cookie becomes a record reference to look up a key an 'is an instance of a reference' and not a 'is an instance of a user', which is valuable when you consider that SSL is totally compromised by design. This could be used in AJAX type scenarios wherein the underlying API derives a session key and the AJAX data is encrypted with it, so even a full compromise of all data by an attacker still does not result in a compromise of the session. I may not have implemented the keying logic fully well, I intended to review it and sort it out after I got the basic components working.

And all of this was intended to fuel research on SGX security, however like ABSOLUTELY EVERYTHING in my life, someone has apparently decided its totally cool to constantly sabotage everything I try to do and from time to time decides to steal it, which somehow isn't industrial espionage or industrial sabotage because that's not what it is when they do it.

First people started in with distractions, then when that didn't work someone came through with an idea that at face value looks better but lacks sufficient depth and has some problems in design and implementation when that didn't discourage me, my code started changing to reintroduce bugs I had already fixed, when that didn't stop me me the hashing routines would strangely work everytime exact for the last iteration, then my network was tampered with so that it took days to obtain a debugger. This same thing seems to sometimes happen with my code stored server side, it changes from what I wrote and bugs are introduced to it, so when I pick up old projects there are things that I didn't write that I'm forced to sort out-- its a recursive series of puzzles with a sole purpose of destroying my ability to support myself, and because of the misuse of medical science, rigging of courts and so on, they absolutely constitute crimes against humanity.

At which point, after years of this I arrived at my foaming, angry, barking state which induces the need to take sleeping pills, which as it turns out apparently aren't even sleeping pills because they keep me awake, cause this bizarre emotional state and keep me in a perpetual daze, but don't help me sleep. This made debugging implausible because I'd forget what line of assembly I had just read immediately after reading it.

When I sorted that out and discerned I needed to wipe the computer for travel anyway, I discovered the thumb drive with the copy of the compiler I needed had been disappeared from my home. So when I went to go redownload it I found that its apparently entirely disappeared from the internet and VS2015 professional no longer seems to exist irrelevant of computer or network.

Further, when I attempt to work in manners that produce potentially useful products that I might be able to use to support myself, I am sabotaged. So I started doing bug bounties and turned in some shallow but legitimate bugs only to find they just didn't close bug reports and so I never got paid. In other instances, the payout was significantly lower than it should have been and they just declared they had paid me when they had not-- so I'm not allowed to work, I'm not allowed to be self-employed and I'm not allowed to free-agent with bounties.

In this way, in addition to the creation of loops that forcibly keep me broke and subsidizing specific industry, I have been held someplace against my will for a very long time. Even the government records have been changed to reflect that actually, no I had enough money to leave, but the records are mostly false.

Finally, at my last employer, I paid approximately an effective tax rate of about 50% which is a little more nuanced than just that, but in the "freedom village" that I'm arbitrarily detained in, I can't get the police to even take a criminal complaint on all of the intrusions occurring to me, my mail just vanishes sometimes, and on and on and on.
