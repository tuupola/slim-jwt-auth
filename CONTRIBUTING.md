# Contributing

## Thanks for contributing!

Following these guidelines improves the possibility of your pull request to get accepted. They also help to save everyones time.

## Only one feature or change per pull request

Pull request should contain only one feature or change. For example you have fixed a bug and optimized some code. Optimization is not related to the bug. These should be submitted as two separate pull requests.

## Discuss new features first

Before sending a totally new feature it is a good idea to discuss it first. If you have an idea open an issue about it. Maybe there already is a way to achieve what you are after.

## Write meaningful commit messages

Proper commit message is a full sentence. It starts with capital letter but does not end with period. The GitHub default `Update filename.js` is not enough. When needed include also longer explanation what the commit does.

```
Capitalized, short (50 chars or less) summary

More detailed explanatory text, if necessary.  Wrap it to about 72
characters or so.  In some contexts, the first line is treated as the
subject of an email and the rest of the text as the body.  The blank
line separating the summary from the body is critical (unless you omit
the body entirely); tools like rebase can get confused if you run the
two together.
```

When in doubt see Tim Pope's blogpost [A Note About Git Commit Messages](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)

## Follow the existing coding standards

Code should look like it is written by one person. Follow the original coding standard. It might be different than yours but it is not a holy war. This project uses **[PSR-2 Coding Standard](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)**.

## Include tests

New features and bugfixes should have an accompanying tests. This single thing greatly improves the possibility of pull request being approved.

## Test before committing

You can run tests either manually or automatically on every code change. Automatic tests require [entr](http://entrproject.org/) to work.

``` bash
$ make test
```
``` bash
$ brew install entr
$ make watch
```

## Send coherent history

Make sure each individual commit in your pull request is meaningful. If you had to make multiple intermediate commits while developing, please squash them before submitting.
