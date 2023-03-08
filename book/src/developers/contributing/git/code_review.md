# Code review

## Reviewing

Every team member is responsible for reviewing code. The designations :speech_balloon:, :heavy_check_mark:, and :x: **should** be left by a reviewer as follows:

- :speech_balloon: (Comment) should be used when there is not yet an opinion on overall validity of complete PR, for example:
  - comments from a partial review
  - comments from a complete review on a Work in Progress PR
  - questions or non-specific concerns, where the answer might trigger an expected change before merging
- :heavy_check_mark: (Approve) should be used when the reviewer would consider it acceptable for the contributor to merge, *after addressing* all the comments. For example:
  - style nitpick comments
  - compliments or highlights of excellent patterns ("addressing" might be in the form of a reply that defines scenarios where the pattern could be used more in the code, or a simple :+1:)
  - a specific concern, where multiple reasonable solutions can adequately resolve the concern
  - a Work in Progress PR that is far enough along
- :x: (Request changes) should be used when the reviewer considers it unacceptable to merge without another review of changes that address the comments. For example:
  - a specific concern, without a satisfactory solution in mind
  - a specific concern with a satisfactory solution provided, but *alternative* solutions **may** be unacceptable
  - any concern with significant subtleties

## Responding

Contributors **should** react to reviews as follows:
- :x: if *any* review is marked as "Request changes":
  - make changes and/or request clarification
  - **should not** merge until reviewer has reviewed again and changed the status
- (none) if there are no reviews, contributor should not merge.
- :speech_balloon: if *all* reviews are comments, then address the comments. Otherwise, treat as if no one has reviewed the PR.
- :heavy_check_mark: if *at least one* review is Approved, contributor **should** do these things before merging:
  - make requested changes
  - if any concern is unclear in any way, ask the reviewer for clarification before merging
  - solve a concern with suggested, or alternative, solution
  - if the reviewer's concern is clearly a misunderstanding, explain and merge. Contributor should be on the lookout for followup clarifications on the closed PR
  - if the contributor simply disagrees with the concern, it would be best to communicate with the reviewer before merging
  - if the PR is approved as a work-in-progress: consider reducing the scope of the PR to roughly the current state, and merging. (multiple smaller PRs is better than one big one)

It is also recommended to use the emoji responses to signal agreement or that
you've seen a comment and will address it rather than replying.  This reduces
github inbox spam.

Everyone is free to review any pull request.

Recommended Reading:

 - [How to Do Code Reviews Like a Human](https://mtlynch.io/human-code-reviews-1/)
