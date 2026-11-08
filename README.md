# Roblox security skills

Two agent skills for keeping Roblox games free of backdoors from free models.

I wrote these after malicious Creator Store models got into games I was building. One showed a fake error asking me to paste code into the Studio command bar. Others hid loaders that pull in remote modules. The skills cover the tricks I found.

## Skills

| Skill | When to use it |
|---|---|
| [`model-downloader`](skills/model-downloader/SKILL.md) | Before inserting any model, module or script from the Creator Store or another outside source. It scans the asset for backdoors, hidden loaders and lures. |
| [`post-compromise-cleanup`](skills/post-compromise-cleanup/SKILL.md) | After malware is found in a game. It walks through containment, a full sweep, removal, verification, recovery and reporting. |

## What they look for

- `require` with an asset ID, including IDs stored in attributes or value objects, or computed at runtime
- Dead drops: a module ID decoded from another asset's description with `GetProductInfo`, so the attacker can change the payload without touching your game
- Code that only runs on live servers or in published games, such as `IsStudio`, `JobId` and `CreatorId` checks
- Obfuscation: `string.char` and `string.byte` decoding, reversed strings, base64 and `loadstring`
- Code, IDs and lures hidden outside scripts, in attributes, tags, value objects and GUI text
- Fake errors that ask a developer to paste code into the command bar
- Fake author credits, persistence tricks and self-deleting scripts

## Using them

They are written for Roblox Studio's Assistant. They refer to its tools, such as `script_read`, `script_grep`, `search_game_tree` and `inspect_instance`. Other agents with access to a Studio session may be able to follow them too.

Each skill is one `SKILL.md` file with a name and description at the top.

## Limits

- These skills have not been tested end to end yet.
- A clean scan means nothing was found. It does not prove an asset or game is safe.
- Some loaders only run on live servers, so a quiet playtest proves nothing.
- Attackers change their tricks. Treat these as a checklist, not a guarantee.

The safest rule is still the simplest one: only use models you made yourself or ones published by Roblox.

## License

[Apache 2.0](LICENSE)
