# Team Rotation - aka "Flamingo" 🦩

Recently, we started a new process. It is evolving, so this doc will evolve with it.

Every Monday, a full-time member of trin rotates into a maintenance position. The person in that role is called the "Flamingo" ([truly amazing animals](https://www.reddit.com/r/Flamingo/comments/odzxry/are_flamingos_extremophiles/)).

Some responsibilities for the Flamingo are:
- monitor glados & hive to watch for regressions; investigate & resolve them
- answer questions from other Portal teams
- run releases & deployments
- review PRs that are stuck
- add documentation & build tools
- fun integrations, like Discord bots

The idea is to set aside normal coding progress for the week, to take care of these important and often overlooked tasks.

## Responsibilities

There are some daily tasks, and some transition tasks: Kickoff on Monday & Handoff on Friday.

Unlike your code-heavy weeks, this can be an interruption-heavy week. Although it's often good practice to not get distracted by inbound messages while coding, this week is the opposite: as soon as you see new messages (like on Discord), jump into it.

Start with Kickoff on Monday morning:

### Kickoff

At the end of the previous week, you will get the [Flamingo notes](https://notes.ethereum.org/YAiNsmc8SSq05TwYdk-8Eg) from the previous Flamingo. They will include incidents from the prior weeks and any in-progress tasks. This will be crucial to get a quick understanding of the state of the network and any in-progress tasks to resume.

Read through the notes, and then generate the new checklist for the week, by [creating a note from this template](https://notes.ethereum.org/?nav=overview&template=b35733cd-b374-4b79-bc57-f2bb58ee651e).

Link the generated checklist into the Flamingo notes for your week. Make sure your status is "online" in Discord. Make sure you're tagged under the `trin-flamingo` role. Put on your favorite pink shirt. Listen to the [flamingo anthem](https://www.youtube.com/watch?v=6hJv5yBLe9c). Fly.

### Daily

#### Checklist

Every day, go down the checklist for that day of the week, resolve items and check them off. If you think of new daily things to add to the checklist, comment on the template to suggest it.

As long as there aren't any major incidents, you should finish the checklist with plenty of time left in your day. See [Maintenance Inspiration](#maintenance-inspiration) for what to do for the rest of the day.

#### Maintenance Inspiration

When you get to the end of your checklist, here are ideas for what to work on next:
- Respond to [Github Participating Notifications](https://github.com/notifications?query=reason%3Aparticipating)
- Review PRs that have been stuck for >24 hours
- Find a [Flamingo Issue](https://github.com/ethereum/trin/issues?q=is%3Aopen+is%3Aissue+label%3Aflamingo) that seems promising, and assign it to yourself (and the project dashbord)
- grep code for `TODO`s. For each one you find:
  - write up issue to explain what needs to be done, and a plan
  - link to the TODO in the code, and any relevant context
  - label issue as Flamingo. If it is not urgent and a good fit, add "Good First Issue"
  - Post a PR to remove the `TODO` from the code, in favor of the issue.
  - `git grep -i "todo"` & `git grep -i "fixme"`
- Look through all [open trin issues](https://github.com/ethereum/trin/issues)
  - Close outdated issues, with a short explanation
  - If appropriate, add a Flamingo tag
  - Sort by "Least Recently Updated" and tackle the most stale issues, until the stale issue bot is active & we've caught up to date with 0 stale issues.
- Write new portal-hive tests
  - The first step is to make an issue with a list of test ideas, or take over [this one](https://github.com/ethereum/portal-hive/issues/54)
  - Add new portal-hive test ideas to the list
  - Claim one of the ideas of the list to work on
- Respond to all [trin repo activity](https://github.com/notifications?query=repo%3Aethereum%2Ftrin)
- Add new integration tools (eg~ portal-hive -> Discord bot?)
- Scratch your own itch! What do you wish was easier? Now is the time to build it.

Be sure to update the week's notes as you go, adding: notable incidents, summaries of what you are working on, and ideas for future work.

### Handoff

Before handing off the notes on Friday, be sure to read through the notes to cleanly summarize the week's activities. Link to any helpful issues, and delete any text that is only meaningful to you.

Think through: what kinds of things do you wish were on the notes that you got on Monday?

After a while, everyone should have the Flamingo Notes link. Sending the link anyway helps accomplish a few things:
1. Signal to the next Flamingo that you're done writing up the notes
2. Give the next Flamingo a reminder that their turn is coming up
3. A failsafe to make sure we didn't forget to pick a Flamingo for the following week

Especially while we continue to develop the procedure, try to be available the following Monday to help the subsequent Flamingo transition in, and get started.

## Being the Announcer

The Flamingo is often the first to notice downtime. Whether it's something that affects users or developers, announce the downtime and link to status updates as soon as possible. Also, announce when the downtime is over.

## *Not* Flamingo

If you're not Flamingo currently, there are some situations where it is important to ping the Flamingo in Discord with `@flamingo-trin`. For example:
- You notice the network behaving abnormally
- You notice any of our tooling behaving abnormally (github, Circle, glados, etc)
- You have a PR that has had no review activity after asking more than 24 hours ago
- You are doing anything that affects other people, like:
  - planned downtime
  - a team-wide configuration change in CircleCI
  - deploying a new tool

Naturally, before writing it in chat, look for a pre-existing announcement from the Flamingo. Maybe they already figured it out, which means they have already announced it, and we don't need the duplicate message.
