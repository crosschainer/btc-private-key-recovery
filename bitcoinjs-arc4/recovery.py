"""Bounded ARC4 state enumeration and full synthetic observation replay."""
import itertools
import time
import pipeline as p
FIT=(32,48,64)

def require(value, message):
    if not value:
        raise ValueError(message)


def configurations():
    return [dict(zip(("branch", "start_index", "mask"), row))
            for row in itertools.product((0, 1), (0, 1), ("low", "high"))]


def validate_recipes(recipes):
    require(isinstance(recipes, list) and recipes, "Need at least one explicit recipe")
    seen = set()
    for recipe in recipes:
        require(set(recipe) == {"id", "multiplier", "times_ms", "extra_seed_ints", "stream_offset", "rationale"},
                "Recipe requires exact id/multiplier/times_ms/extra_seed_ints/stream_offset/rationale fields")
        require(isinstance(recipe["id"], str) and recipe["id"] and recipe["id"] not in seen, "Duplicate/empty recipe ID")
        require(isinstance(recipe["rationale"], str) and recipe["rationale"], "Explain each timing assumption")
        require(isinstance(recipe["times_ms"], list) and isinstance(recipe["extra_seed_ints"], list), "Expected event lists")
        p.seed_for_state(recipe["multiplier"], 1, recipe["times_ms"], recipe["extra_seed_ints"],
                         boundary="after", stream_offset=recipe["stream_offset"])
        seen.add(recipe["id"])


def seed_at(recipe, state):
    return p.seed_for_state(recipe["multiplier"], state, recipe["times_ms"], recipe["extra_seed_ints"],
                            boundary="after", stream_offset=recipe["stream_offset"])


def check_seed(seed, values, configs, fit_indices=FIT):
    """Filter on fixed informative observations; replay all others on survivors.

    Cache source children across masks/starts; never count the forced bit.
    An exceptional scalar raises, leaving the chunk incomplete rather than
    converting an unsupported candidate into a negative result.
    """
    require(len(fit_indices) >= 3 and len(set(fit_indices)) == len(fit_indices), "Need three distinct fitting observations")
    require(all(n in values and n > 1 for n in fit_indices), "Missing/uninformative fitting observations")
    account = p.derive(p.master(seed), p.HARDENED)
    parents, children, matches = {}, {}, []
    fit_survivors = 0
    for config in configs:
        branch, start, mask = config["branch"], config["start_index"], config["mask"]
        if branch not in parents:
            parents[branch] = p.derive(account, branch)

        def value(number):
            key = (branch, start + number - 1)
            p.integer(key[1], 0, p.HARDENED - 1, "child index")
            if key not in children:
                children[key] = p.derive(parents[branch], key[1]).scalar
            return p.mask_scalar(children[key], number, mask)

        if not all(value(n) == values[n] for n in fit_indices):
            continue
        fit_survivors += 1
        if all(value(n) == values[n] for n in sorted(values) if n not in fit_indices):
            matches.append(dict(config))
    return {"fit_survivors": fit_survivors, "matches": matches}


def scan_interval(recipe, begin, end, values, configs=None, fit_indices=FIT):
    configs = configurations() if configs is None else configs
    limit = recipe["multiplier"] * 65535 + 65535 + 1
    p.integer(begin, 1, limit - 1, "first after-call state")
    p.integer(end, begin + 1, limit, "exclusive state end")
    started = time.monotonic()
    matches, survivors = [], 0
    for state in range(begin, end):
        result = check_seed(seed_at(recipe, state), values, configs, fit_indices)
        survivors += result["fit_survivors"]
        matches.extend({"state_after_first_call": state, "config": config} for config in result["matches"])
    return {"recipe_id": recipe["id"], "begin": begin, "end": end, "complete": True,
            "states_checked": end - begin, "configuration_checks": (end - begin) * len(configs),
            "fit_survivors": survivors, "matches": matches, "seconds": time.monotonic() - started}
