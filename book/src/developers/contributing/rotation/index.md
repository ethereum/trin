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

### First time ever as Flamingo

Read through the "Setup" section of the [Deployment Instructions](../releases/deployment.md) and follow the steps to make sure that your PGP and SSH keys are in place and ready for a deployment.

### Kickoff: first day of Flamingo week

Have a discussion with the previous Flamingo on any ongoing issues or in-progress tasks. This is crucial to get a quick understanding of the state of the network and any in-progress tasks to resume.

Make sure your status is "online" in Discord. Make sure you're tagged under the `trin-flamingo` role (ping discord Admin). Put on your favorite pink shirt. Watch a [silly flamingo video](https://www.youtube.com/watch?v=gWNWtbPEWw0). Fly.

### Daily

#### Checklist

Every day, go down the daily and items for that day of the week. If you think of new daily things to add to the checklist, create a PR.

- **Daily**
  - Read Discord, especially for help requests or signs of network issues
  - Monitor [Glados](https://glados.ethdevops.io/) changes, and correlate with releases (trin, glados, other clients?)
  - Monitor [portal-hive](https://portal-hive.ethdevops.io/) changes
    - Check the dates, did all test suites run on the previous cycle?
    - For each suite, did the expected number of tests run?
    - Did clients start failing any new tests?
      - If trin failing, create rotation issue to pursue
      - If other client failing, notify the team
  - Look for [inspiration for Flamingo projects](../rotation/index.md#maintenance-inspiration)

- **Monday** - kickoff
  - Announce that you are on rotation in Discord
  - Give yourself the Discord role `@trin-flamingo`
  - Discuss ongoing issues and in-progress tasks with previous Flamingo
  - Give weekly summary update in all-Portal call
  - Pick day of week for deployment (usually Wednesday or Thursday), discuss in `#trin`

- **Wednesday or Thursday** - release
  - [Release](../releases/release_checklist.md) and [deploy](../releases/deployment.md) new version of trin

- **Friday** - wrap-up
  - Haven't deployed yet? Oops, a bit late. Get it done as early as possible.
  - Comment on the checklist to add/update/delete anything?
  - Identify the next Flamingo and prepare for [handoff](#handoff)

As long as there aren't any major incidents, you should finish the checklist with plenty of time left in your day. See [Maintenance Inspiration](#maintenance-inspiration) for what to do for the rest of the day.

#### Maintenance Inspiration

When you get to the end of your checklist, here are ideas for what to work on next:

- Respond to [Github Participating Notifications](https://github.com/notifications?query=reason%3Aparticipating)
- Review PRs that have been stuck for >24 hours
- Find a [Flamingo Issue](https://github.com/ethereum/trin/issues?q=is%3Aopen+is%3Aissue+label%3Aflamingo) that seems promising, and assign it to yourself (and the project dashboard)
- grep code for `TODO`s. For each one you find:
  - write up issue to explain what needs to be done, and a plan
  - link to the TODO in the code, and any relevant context
  - label issue as Flamingo. If it is not urgent and a good fit, add "Good First Issue"
  - Post a PR to remove the `TODO` from the code, in favor of the issue.
  - `git grep -iE "(todo)|(fixme)"`
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

### Handoff: last day of Flamingo week

Look back at your week as Flamingo and summarize it in notes if needed. Prepare for a kickoff discussion with the next Flamingo and update them on your work from previous week.

Especially while we continue to develop the procedure, try to be available the following Monday to help the subsequent Flamingo transition in, and get started.

Think through: what kinds of things do you think should be on the checklist?

Double check the [Flamingo schedule](https://notes.ethereum.org/@njgheorghita/r1angO2lT) and make sure you're available for your next rotation. If not, please switch with somebody asap.

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
