(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.BellatorDraw = factory();
  }
})(this, function() {
  function displayInitial(value, fallback) {
    var text = String(value || '').trim();
    if (!text) return fallback || '?';
    var first = Array.from(text.normalize('NFKC'))[0];
    return first ? first.toUpperCase() : (fallback || '?');
  }

  function normalizeDivisionKey(value) {
    var text = String(value || '').toLowerCase();
    if (text.includes('ciudad')) return 'ciudad';
    if (text.includes('universal')) return 'universal';
    return '';
  }

  function xmur3(value) {
    var text = String(value || '');
    var hash = 1779033703 ^ text.length;
    for (var i = 0; i < text.length; i++) {
      hash = Math.imul(hash ^ text.charCodeAt(i), 3432918353);
      hash = (hash << 13) | (hash >>> 19);
    }
    return function() {
      hash = Math.imul(hash ^ (hash >>> 16), 2246822507);
      hash = Math.imul(hash ^ (hash >>> 13), 3266489909);
      return (hash ^= hash >>> 16) >>> 0;
    };
  }

  function mulberry32(seed) {
    return function() {
      var t = seed += 0x6D2B79F5;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function seededShuffle(items, seedText) {
    var list = items.slice();
    var seed = xmur3(seedText || 'bellator-draw')();
    var random = mulberry32(seed);
    for (var i = list.length - 1; i > 0; i--) {
      var j = Math.floor(random() * (i + 1));
      var temp = list[i];
      list[i] = list[j];
      list[j] = temp;
    }
    return list;
  }

  function createDrawPlayerSlot(player, divisionKey, index) {
    var name = String(player && player.pseudonimo || 'Competidor').trim() || 'Competidor';
    return {
      kind: 'player',
      code: divisionKey.slice(0, 1).toUpperCase() + String(index + 1).padStart(2, '0'),
      name: name,
      note: String(player && player.division || divisionKey).trim() || divisionKey,
      avatar: player && player.avatar_url && player.avatar_url !== '<nil>' ? String(player.avatar_url).trim() : '',
      initial: displayInitial(name, '?')
    };
  }

  function createOpenDrawSlot(divisionKey, index) {
    return {
      kind: 'open',
      code: divisionKey.slice(0, 1).toUpperCase() + 'S' + String(index + 1).padStart(2, '0'),
      name: 'Cupo disponible',
      note: 'Pendiente de cierre',
      avatar: '',
      initial: '+'
    };
  }

  function createFutureDrawSlot(label) {
    return {
      kind: 'future',
      code: label,
      name: 'Ganador ' + label,
      note: 'Cruce por definir',
      avatar: '',
      initial: '?'
    };
  }

  function stablePlayerSlotKey(player, fallbackIndex) {
    var timestamp = String(player && player.timestamp || '').trim();
    if (timestamp) return 'ts:' + timestamp;
    var name = String(player && player.pseudonimo || '').trim().toLowerCase();
    if (name) return 'pseudo:' + name;
    return 'idx:' + String(fallbackIndex || 0);
  }

  function buildSeededSlots(players, divisionKey, bracketSize, seedKey) {
    var actual = players.slice(0, bracketSize).map(function(player, index) {
      return createDrawPlayerSlot(player, divisionKey, index);
    });
    var open = Array.from({ length: Math.max(0, bracketSize - actual.length) }, function(_, index) {
      return createOpenDrawSlot(divisionKey, index);
    });
    return seededShuffle(actual.concat(open), seedKey).slice(0, bracketSize);
  }

  function buildOrderedSlots(players, divisionKey, bracketSize) {
    var actual = players.slice(0, bracketSize).map(function(player, index) {
      return createDrawPlayerSlot(player, divisionKey, index);
    });
    var open = Array.from({ length: Math.max(0, bracketSize - actual.length) }, function(_, index) {
      return createOpenDrawSlot(divisionKey, index);
    });
    return actual.concat(open).slice(0, bracketSize);
  }

  function buildProgressiveSlots(players, divisionKey, bracketSize, seedKey) {
    var size = Math.max(0, bracketSize || 0);
    var slots = Array.from({ length: size }, function() { return null; });
    players.slice(0, size).forEach(function(player, playerIndex) {
      var available = [];
      for (var slotIndex = 0; slotIndex < size; slotIndex++) {
        if (!slots[slotIndex]) available.push(slotIndex);
      }
      if (!available.length) return;
      var playerSeed = String(seedKey || 'bellator-fixed-slots')
        + '|' + String(divisionKey || '')
        + '|' + stablePlayerSlotKey(player, playerIndex);
      var targetIndex = seededShuffle(available, playerSeed)[0];
      slots[targetIndex] = createDrawPlayerSlot(player, divisionKey, targetIndex);
    });
    return slots.map(function(slot, index) {
      return slot || createOpenDrawSlot(divisionKey, index);
    });
  }

  function buildSideRounds(firstRoundMatches, divisionKey, sideKey) {
    var prefix = divisionKey.slice(0, 1).toUpperCase() + sideKey;
    var rounds = [];
    var current = firstRoundMatches.map(function(teams, index) {
      return { code: prefix + String(index + 1), teams: teams };
    });
    rounds.push(current);
    while (current.length > 1) {
      var next = [];
      for (var i = 0; i < current.length; i += 2) {
        next.push({
          code: prefix + String(rounds.length + 1) + String((i / 2) + 1),
          teams: [
            createFutureDrawSlot(current[i].code),
            createFutureDrawSlot(current[i + 1].code)
          ]
        });
      }
      rounds.push(next);
      current = next;
    }
    return rounds;
  }

  function buildStandardDrawModelFromSlots(slots, divisionKey) {
    var firstRoundMatches = [];
    for (var index = 0; index < slots.length; index += 2) {
      firstRoundMatches.push([slots[index], slots[index + 1]]);
    }
    var half = firstRoundMatches.length / 2;
    return {
      left: buildSideRounds(firstRoundMatches.slice(0, half), divisionKey, 'L'),
      right: buildSideRounds(firstRoundMatches.slice(half), divisionKey, 'R')
    };
  }

  function buildDrawModelFromSlots(slots, divisionKey, bracketSize) {
    return buildStandardDrawModelFromSlots(slots, divisionKey);
  }

  function buildPairingMatchesFromSlots(slots, divisionKey) {
    var prefix = divisionKey.slice(0, 1).toUpperCase();
    var matches = [];
    for (var index = 0; index < slots.length; index += 2) {
      matches.push({
        code: prefix + String((index / 2) + 1),
        teams: [slots[index], slots[index + 1]]
      });
    }
    return matches;
  }

  function buildOrderedPairingMatches(players, divisionKey, bracketSize) {
    var slots = buildOrderedSlots(players, divisionKey, bracketSize);
    return buildPairingMatchesFromSlots(slots, divisionKey);
  }

  function buildDrawModel(players, divisionKey, bracketSize, seedKey) {
    var slots = buildSeededSlots(players, divisionKey, bracketSize, seedKey);
    return buildDrawModelFromSlots(slots, divisionKey, bracketSize);
  }

  function buildOrderedDrawModel(players, divisionKey, bracketSize) {
    var slots = buildOrderedSlots(players, divisionKey, bracketSize);
    return buildDrawModelFromSlots(slots, divisionKey, bracketSize);
  }

  function buildProgressiveDrawModel(players, divisionKey, bracketSize, seedKey) {
    var slots = buildProgressiveSlots(players, divisionKey, bracketSize, seedKey);
    return buildDrawModelFromSlots(slots, divisionKey, bracketSize);
  }

  function makeDrawSeed(seedInfo, rosterSeed) {
    var seedPart = (seedInfo && !seedInfo.fallback && seedInfo.randomness)
      ? String(seedInfo.randomness)
      : 'bellator-fallback';
    return seedPart + '|' + String(rosterSeed || '');
  }

  return {
    normalizeDivisionKey: normalizeDivisionKey,
    seededShuffle: seededShuffle,
    createDrawPlayerSlot: createDrawPlayerSlot,
    createOpenDrawSlot: createOpenDrawSlot,
    createFutureDrawSlot: createFutureDrawSlot,
    buildOrderedSlots: buildOrderedSlots,
    buildProgressiveSlots: buildProgressiveSlots,
    buildSeededSlots: buildSeededSlots,
    buildSideRounds: buildSideRounds,
    buildOrderedPairingMatches: buildOrderedPairingMatches,
    buildOrderedDrawModel: buildOrderedDrawModel,
    buildProgressiveDrawModel: buildProgressiveDrawModel,
    buildDrawModel: buildDrawModel,
    makeDrawSeed: makeDrawSeed
  };
});
