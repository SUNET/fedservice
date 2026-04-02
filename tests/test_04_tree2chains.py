from fedservice.entity.function import tree2chains


def test_tree2chains_1():
    tree = {
        "https://example.com/rp": (
            'statement1', {
                "https://example.com/intermediate1": (
                    'statement2', {
                        "https://example.com/anchor": (
                            "statement3", {})})})}

    chains = tree2chains(tree)
    assert len(chains) == 1
    assert len(chains[0]) == 3
    assert chains[0] == ["statement3", "statement2", "statement1"]


def test_tree2chains_2():
    tree = {
        "https://example.com/rp": (
            'statement1', {
                "https://example.com/intermediate1": (
                    'statement2', {
                        "https://example.com/anchor1": ("statement3", {}),
                        "https://example.com/anchor2": ("statement4", {})
                    })})}

    chains = tree2chains(tree)
    assert len(chains) == 2
    assert chains[0] == ["statement3", "statement2", "statement1"]
    assert chains[1] == ["statement4", "statement2", "statement1"]


def test_tree2chains_3():
    tree = {
        "https://example.com/rp": (
            'statement1', {
                "https://example.com/intermediate1": (
                    'statement2', {
                        "https://example.com/anchor1": ("statement3", {})
                    }
                ),
                "https://example.com/intermediate2": (
                    'statement5', {
                        "https://example.com/anchor2": ("statement4", {})
                    }
                )
            })}

    chains = tree2chains(tree)
    assert len(chains) == 2
    assert chains[0] == ["statement3", "statement2", "statement1"]
    assert chains[1] == ["statement4", "statement5", "statement1"]


def test_tree2chains_4():
    tree = {
        "https://example.com/rp": (
            'statement1', {
                "https://example.com/intermediate1": (
                    'statement2', {
                        "https://example.com/anchor1": ("statement3", {})
                    }
                ),
                "https://example.com/intermediate2": (
                    'statement5', {
                        "https://example.com/anchor1": ("statement3", {})
                    }
                )
            })}

    chains = tree2chains(tree)
    assert len(chains) == 2
    assert chains[0] == ["statement3", "statement2", "statement1"]
    assert chains[1] == ["statement3", "statement5", "statement1"]

def test_tree2chains_a():
    tree = {
        'https://intermediate.example.org': (
            'statement1', {
                'https://ta.example.org': (
                    'statement2', {}
                )
            }
        ),
        'https://intermediate2.example.org': (
            'statement3', {
                'https://ta.example.org': (
                    'statement4', {}
                )
            }
        )
    }
    chains = tree2chains(tree)
    assert len(chains) == 2
    assert chains[0] == ['statement2', 'statement1']
    assert chains[1] == ['statement4', 'statement3']

def test_tree2chains_5():
    tree = {
        "https://example.com/rp": (
            'statement1', {
                "https://example.com/intermediate1": (
                    'statement2', {
                        "https://example.com/anchor1": ("statement3", {})
                    }
                ),
                "https://example.com/anchor2": ("statement4", {})
            })}

    chains = tree2chains(tree)
    assert len(chains) == 2
    assert chains[0] == ["statement3", "statement2", "statement1"]
    assert chains[1] == ["statement4", "statement1"]

