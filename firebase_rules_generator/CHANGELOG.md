## 0.3.4

- Remove `as <type>` casts from generated rules. This allows for more type flexibility when writing Dart code.

## 0.3.3

- Fix `JsonKeyRewriter` only checking `mixins`. Now it checks type directly and all `supertypes`.

## 0.3.2

- Support `is` operator by using Dart, `cloud_firestore`, and `firestore_rules` model data types.

## 0.3.1

- Fix sanitization: Regex for converting `contains` and `range` were overmatching. For example `rules.raw('foo == bar') && (!request.resource.data.rules().keys().contains('id') || rules.raw('foo == bar'))` would result in `'id' in foo == bar && (!request.resource.data.keys() || foo == bar)`, but should have been `foo == bar && (!('id' in request.resource.data.keys()) || foo == bar)`.

## 0.3.0

- Fix sanitization: Regex collisions in replacing "non-braces string interpolation" 
- Fix sanitization: Leaves `!` and `?` in front of `.rules()`. For example `resource.data.userId!.rules()` did output `resource.data.userId!` instead of `resource.data.userId`.

- BREAKING:
  `@JsonKey` annotated fields are now rewritten using the name specified in the annotation. For example, if you have a field `@JsonKey(name: 'user_id') String userId;`, something like `resource.data.userId.rules()` will now output `resource.data.user_id`.

## 0.2.3

- Supports analyzer 7
- Fixes analysis issues

## 0.2.2

- Uses the `default` Firestore database if none is specified in Storage rules

## 0.2.1

- Support for `firebase_rules: ^0.2.0`

## 0.2.0

- BREAKING: Proper function signatures are now enforced

## 0.1.1

- Dependency upgrades

## 0.1.0

- Updates to support `firebase_rules` changes
- Translate `r"..."` to `"..."` instead of `'...'`
- Strip null check (`!`) operators
- Ignore paths that equal `_`
- Database string `matches(regex)` regex now must include the leading and trailing `/`
- Fixes issue with raw matching
- Raws are now completely ignored during sanitization
- Improvements to string interpolation handling
- `rules.path('/path/to/resource')` now translates to `/path/to/resource`
- Fixed handling of `!type.contains()`

## 0.0.1

- Initial release

## 0.0.0

- Early bird special
