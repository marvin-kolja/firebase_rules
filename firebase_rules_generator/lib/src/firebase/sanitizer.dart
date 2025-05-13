import 'package:firebase_rules/firebase.dart';
import 'package:firebase_rules_generator/src/common/sanitizer.dart';
import 'package:firebase_rules_generator/src/firebase/revived_firebase_rules.dart';

/// Sanitize rules files
String sanitizeRules(RevivedFirebaseRules annotation, String input) {
  return transformIgnoringRaws(input, [
    stripNullSafety,
    removeRulesPrefixesAndSuffixes,
    translateRawStrings,
    (input) => input
        // Convert non-braced string interpolation
        // TODO: Maybe needs work to avoid collisions
        .replaceAllMapped(RegExp(r'\$([a-zA-Z_]\w*)'), (m) => '\$(${m[1]})')
        // Convert braced string interpolation
        // TODO: Maybe needs work to avoid collisions
        .replaceAllMapped(RegExp(r'\${(.+?)}'), (m) => '\$(${m[1]})'),
    (input) => input
            // Convert firestore methods
            .replaceAllMapped(
          RegExp(r'firestore\.(.+?)(<.+?>)?\((.+?)\)'),
          (m) {
            final buffer = StringBuffer();
            if (annotation.service != Service.firestore) {
              buffer.write('firestore.');
            }
            buffer.write('${m[1]}(${m[3]})');
            return buffer.toString();
          },
        )
            // Translate all paths
            .replaceAllMapped(
          RegExp(r"path\('(.+?)'(, database: '(.+?)')?\)"),
          (m) {
            final databaseParam = m[3];
            final String database;
            if (databaseParam == null) {
              if (annotation.service == Service.firestore) {
                // Use the database wildcard for Firestore rules
                database = '\$(database)';
              } else {
                // Otherwise use the default database
                database = '(default)';
              }
            } else {
              database = '($databaseParam)';
            }
            return 'path(\'/databases/$database/documents${m[1]}\')';
          },
        )
            // Convert path strings to raw paths
            .replaceAllMapped(
          RegExp(r"path\('(.+?)'\)(\.bind\((.+?)\))?"),
          (m) => m[2] != null ? '(${m[1]}).bind(${m[3]})' : m[1]!,
        ),
    (input) => input
            // Convert `contains` to `x in y`
            .replaceAllMapped(
          RegExp(
              r'(!)?([a-zA-Z_]+?(?:[a-zA-Z_\d]|\.|\([^\n^(\r]*?\))*?)\.contains\((.+?)\)'),
          (m) {
            if (m[1] != null) {
              return '!(${m[3]} in ${m[2]})';
            } else {
              return '${m[3]} in ${m[2]}';
            }
          },
        )
            // Convert `range` to `x[i:j]
            .replaceAllMapped(
          RegExp(
              r'([a-zA-Z_]+?[a-zA-Z_\d]+?(?:\([^\n^(\r]*?\))?)\.range\((.+?), (.+?)\)'),
          (m) => '${m[1]}[${m[2]}:${m[3]}]',
        ),
    (input) => input
        // bool parsing
        .replaceAllMapped(RegExp(r'parseBool\((.+?)\)'), (m) => 'bool(${m[1]})')
        // bytes parsing
        .replaceAllMapped(RegExp(r"parseBytes\('(.+?)'\)"), (m) => "b'${m[1]}'")
        // float parsing
        .replaceAllMapped(
          RegExp(r'parseFloat\((.+?)\)'),
          (m) => 'float(${m[1]})',
        )
        // int parsing
        .replaceAllMapped(RegExp(r'parseInt\((.+?)\)'), (m) => 'int(${m[1]})'),
    (input) => translateEnums(input, {
          'RulesDurationUnit': RulesDurationUnit.values,
          'RulesMethod': RulesMethod.values,
          'RulesIdentityProvider': RulesIdentityProvider.values,
          'RulesSignInProvider': RulesSignInProvider.values,
        }),
    (input) => translateUserEnums(input, annotation.enums),
    translateAuthVariables,
    (input) => input.replaceAll(
          'resource.firestoreResourceName',
          "resource['__name__']",
        ),

    /// Replaces all `is <type>` with the corresponding firestore type.
    ///
    /// It does not include `constraint` data type.
    ///
    /// ref: https://firebase.google.com/docs/firestore/security/rules-fields#enforcing_field_types
    (input) => input.replaceAllMapped(
            RegExp(
              r'\sis\s+(bool|Blob|double|int|List|GeoPoint|num|Map|String|Timestamp|Set|RulesPath|MapDiff|RulesDuration)',
            ), (m) {
          const map = {
            'bool': 'bool',
            'Blob': 'bytes',
            'double': 'float',
            'int': 'int',
            'List': 'list',
            'GeoPoint': 'latlng',
            'num': 'number',
            'RulesPath': 'path',
            'Map': 'map',
            'String': 'string',
            'Timestamp': 'timestamp',
            'RulesDuration': 'duration',
            'Set': 'set',
            'MapDiff': 'map_diff',
          };

          if (!map.containsKey(m[1])) {
            return ' is ${m[1]}';
          }

          return ' is ${map[m[1]]}';
        }),
    /// Remove all `as <type>` and `as <type>?` casts.
    ///
    /// TODO: Remove parathesis around such casts, e.g. `(foo as Type).bar`
    (input) => input.replaceAll(
          RegExp(r'\s+as\s+\w+\??'),
          '',
        ),
  ]);
}

/// Extract raw rules strings, replace them with placeholders, sanitize the
/// input, then replace the placeholders with the raw rules strings
String transformIgnoringRaws(
  String input,
  List<String Function(String input)> transforms,
) {
  final raws = <String>[];
  input = input.replaceAllMapped(
      RegExp(r'''rules\.raw(<.+?>)?\(['"](.+?)['"]\)'''), (m) {
    raws.add(m[2]!);
    return '{RulesRawPlaceholder${raws.length - 1}}';
  });

  input = transform(input, transforms);

  for (var i = 0; i < raws.length; i++) {
    input = input.replaceFirst('{RulesRawPlaceholder$i}', raws.elementAt(i));
  }

  return input;
}
