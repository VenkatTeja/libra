
<a name="0x1_Stats"></a>

# Module `0x1::Stats`



-  [Struct `SetData`](#0x1_Stats_SetData)
-  [Resource `ValStats`](#0x1_Stats_ValStats)
-  [Function `initialize`](#0x1_Stats_initialize)
-  [Function `blank`](#0x1_Stats_blank)
-  [Function `init_address`](#0x1_Stats_init_address)
-  [Function `init_set`](#0x1_Stats_init_set)
-  [Function `process_set_votes`](#0x1_Stats_process_set_votes)
-  [Function `node_current_votes`](#0x1_Stats_node_current_votes)
-  [Function `node_above_thresh`](#0x1_Stats_node_above_thresh)
-  [Function `network_density`](#0x1_Stats_network_density)
-  [Function `node_current_props`](#0x1_Stats_node_current_props)
-  [Function `inc_prop`](#0x1_Stats_inc_prop)
-  [Function `inc_vote`](#0x1_Stats_inc_vote)
-  [Function `reconfig`](#0x1_Stats_reconfig)
-  [Function `get_total_votes`](#0x1_Stats_get_total_votes)
-  [Function `get_total_props`](#0x1_Stats_get_total_props)
-  [Function `get_history`](#0x1_Stats_get_history)
-  [Function `test_helper_inc_vote_addr`](#0x1_Stats_test_helper_inc_vote_addr)


<pre><code><b>use</b> <a href="CoreAddresses.md#0x1_CoreAddresses">0x1::CoreAddresses</a>;
<b>use</b> <a href="Debug.md#0x1_Debug">0x1::Debug</a>;
<b>use</b> <a href="Errors.md#0x1_Errors">0x1::Errors</a>;
<b>use</b> <a href="FixedPoint32.md#0x1_FixedPoint32">0x1::FixedPoint32</a>;
<b>use</b> <a href="Signer.md#0x1_Signer">0x1::Signer</a>;
<b>use</b> <a href="Testnet.md#0x1_Testnet">0x1::Testnet</a>;
<b>use</b> <a href="Vector.md#0x1_Vector">0x1::Vector</a>;
</code></pre>



<a name="0x1_Stats_SetData"></a>

## Struct `SetData`



<pre><code><b>struct</b> <a href="Stats.md#0x1_Stats_SetData">SetData</a>
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>addr: vector&lt;address&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>prop_count: vector&lt;u64&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>vote_count: vector&lt;u64&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>total_votes: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>total_props: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_Stats_ValStats"></a>

## Resource `ValStats`



<pre><code><b>resource</b> <b>struct</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a>
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>history: vector&lt;<a href="Stats.md#0x1_Stats_SetData">Stats::SetData</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>current: <a href="Stats.md#0x1_Stats_SetData">Stats::SetData</a></code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_Stats_initialize"></a>

## Function `initialize`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_initialize">initialize</a>(vm: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_initialize">initialize</a>(vm: &signer) {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190001));
  move_to&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(
    vm,
    <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
      history: <a href="Vector.md#0x1_Vector_empty">Vector::empty</a>(),
      current: <a href="Stats.md#0x1_Stats_blank">blank</a>()
    }
  );
}
</code></pre>



</details>

<a name="0x1_Stats_blank"></a>

## Function `blank`



<pre><code><b>fun</b> <a href="Stats.md#0x1_Stats_blank">blank</a>(): <a href="Stats.md#0x1_Stats_SetData">Stats::SetData</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Stats.md#0x1_Stats_blank">blank</a>():<a href="Stats.md#0x1_Stats_SetData">SetData</a> {
  <a href="Stats.md#0x1_Stats_SetData">SetData</a> {
      addr: <a href="Vector.md#0x1_Vector_empty">Vector::empty</a>(),
      prop_count: <a href="Vector.md#0x1_Vector_empty">Vector::empty</a>(),
      vote_count: <a href="Vector.md#0x1_Vector_empty">Vector::empty</a>(),
      total_votes: 0,
      total_props: 0,
    }
}
</code></pre>



</details>

<a name="0x1_Stats_init_address"></a>

## Function `init_address`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_init_address">init_address</a>(vm: &signer, node_addr: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_init_address">init_address</a>(vm: &signer, node_addr: address) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);

  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190002));

  <b>let</b> stats = borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender);
  <b>let</b> (is_init, _) = <a href="Vector.md#0x1_Vector_index_of">Vector::index_of</a>&lt;address&gt;(&<b>mut</b> stats.current.addr, &node_addr);
  <b>if</b> (!is_init) {
    <a href="Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> stats.current.addr, node_addr);
    <a href="Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> stats.current.prop_count, 0);
    <a href="Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> stats.current.vote_count, 0);
  }
}
</code></pre>



</details>

<a name="0x1_Stats_init_set"></a>

## Function `init_set`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_init_set">init_set</a>(vm: &signer, set: &vector&lt;address&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_init_set">init_set</a>(vm: &signer, set: &vector&lt;address&gt;) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a>{
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190003));
  <b>let</b> length = <a href="Vector.md#0x1_Vector_length">Vector::length</a>&lt;address&gt;(set);
  <b>let</b> k = 0;
  <b>while</b> (k &lt; length) {
    <b>let</b> node_address = *(<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;address&gt;(set, k));
    <a href="Stats.md#0x1_Stats_init_address">init_address</a>(vm, node_address);
    k = k + 1;
  }
}
</code></pre>



</details>

<a name="0x1_Stats_process_set_votes"></a>

## Function `process_set_votes`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_process_set_votes">process_set_votes</a>(vm: &signer, set: &vector&lt;address&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_process_set_votes">process_set_votes</a>(vm: &signer, set: &vector&lt;address&gt;) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a>{
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190004));

  <b>let</b> length = <a href="Vector.md#0x1_Vector_length">Vector::length</a>&lt;address&gt;(set);
  print(&length);
  <b>let</b> k = 0;
  <b>while</b> (k &lt; length) {
    <b>let</b> node_address = *(<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;address&gt;(set, k));
    <a href="Stats.md#0x1_Stats_inc_vote">inc_vote</a>(vm, node_address);
    k = k + 1;
  }
}
</code></pre>



</details>

<a name="0x1_Stats_node_current_votes"></a>

## Function `node_current_votes`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_node_current_votes">node_current_votes</a>(vm: &signer, node_addr: address): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_node_current_votes">node_current_votes</a>(vm: &signer, node_addr: address): u64 <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190005));
  <b>let</b> stats = borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender);
  <b>let</b> (_, i) = <a href="Vector.md#0x1_Vector_index_of">Vector::index_of</a>&lt;address&gt;(&<b>mut</b> stats.current.addr, &node_addr);
  *<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;u64&gt;(&<b>mut</b> stats.current.vote_count, i)
}
</code></pre>



</details>

<a name="0x1_Stats_node_above_thresh"></a>

## Function `node_above_thresh`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_node_above_thresh">node_above_thresh</a>(vm: &signer, node_addr: address, height_start: u64, height_end: u64): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_node_above_thresh">node_above_thresh</a>(vm: &signer, node_addr: address, height_start: u64, height_end: u64): bool <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a>{
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190006));
  <b>let</b> range = height_end-height_start;
  <b>let</b> threshold_signing = <a href="FixedPoint32.md#0x1_FixedPoint32_multiply_u64">FixedPoint32::multiply_u64</a>(range, <a href="FixedPoint32.md#0x1_FixedPoint32_create_from_rational">FixedPoint32::create_from_rational</a>(1, 100));
  <b>if</b> (<a href="Stats.md#0x1_Stats_node_current_votes">node_current_votes</a>(vm, node_addr) &gt;  threshold_signing) { <b>return</b> <b>true</b> };
  <b>return</b> <b>false</b>
}
</code></pre>



</details>

<a name="0x1_Stats_network_density"></a>

## Function `network_density`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_network_density">network_density</a>(vm: &signer, height_start: u64, height_end: u64): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_network_density">network_density</a>(vm: &signer, height_start: u64, height_end: u64): u64 <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190007));
  <b>let</b> density = 0u64;
  <b>let</b> nodes = *&(borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender).current.addr);
  <b>let</b> len = <a href="Vector.md#0x1_Vector_length">Vector::length</a>(&nodes);
  <b>let</b> k = 0;
  <b>while</b> (k &lt; len) {
    <b>let</b> addr = *(<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;address&gt;(&nodes, k));
    <b>if</b> (<a href="Stats.md#0x1_Stats_node_above_thresh">node_above_thresh</a>(vm, addr, height_start, height_end)) {
      density = density + 1;
    };
    k = k + 1;
  };
  <b>return</b> density
}
</code></pre>



</details>

<a name="0x1_Stats_node_current_props"></a>

## Function `node_current_props`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_node_current_props">node_current_props</a>(vm: &signer, node_addr: address): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_node_current_props">node_current_props</a>(vm: &signer, node_addr: address): u64 <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190008));
  <b>let</b> stats = borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender);
  <b>let</b> (_, i) = <a href="Vector.md#0x1_Vector_index_of">Vector::index_of</a>&lt;address&gt;(&<b>mut</b> stats.current.addr, &node_addr);
  *<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;u64&gt;(&<b>mut</b> stats.current.prop_count, i)
}
</code></pre>



</details>

<a name="0x1_Stats_inc_prop"></a>

## Function `inc_prop`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_inc_prop">inc_prop</a>(vm: &signer, node_addr: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_inc_prop">inc_prop</a>(vm: &signer, node_addr: address) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  print(&0100201);
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190009));
  print(&0100202);
  <b>let</b> stats = borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender);
  print(stats);
  print(&0100203);
  <b>let</b> (t, i) = <a href="Vector.md#0x1_Vector_index_of">Vector::index_of</a>&lt;address&gt;(&<b>mut</b> stats.current.addr, &node_addr);
  print(&t);
  print(&i);
  print(&0100204);
  <b>let</b> current_count = *<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;u64&gt;(&<b>mut</b> stats.current.prop_count, i);
  print(&0100205);
  <a href="Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> stats.current.prop_count, current_count + 1);
  print(&0100206);
  <a href="Vector.md#0x1_Vector_swap_remove">Vector::swap_remove</a>(&<b>mut</b> stats.current.prop_count, i);
  print(&0100207);
  stats.current.total_props = stats.current.total_props + 1;
}
</code></pre>



</details>

<a name="0x1_Stats_inc_vote"></a>

## Function `inc_vote`



<pre><code><b>fun</b> <a href="Stats.md#0x1_Stats_inc_vote">inc_vote</a>(vm: &signer, node_addr: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Stats.md#0x1_Stats_inc_vote">inc_vote</a>(vm: &signer, node_addr: address) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190010));
  <b>let</b> stats = borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender);
  <b>let</b> (_, i) = <a href="Vector.md#0x1_Vector_index_of">Vector::index_of</a>&lt;address&gt;(&<b>mut</b> stats.current.addr, &node_addr);
  <b>let</b> test = *<a href="Vector.md#0x1_Vector_borrow">Vector::borrow</a>&lt;u64&gt;(&<b>mut</b> stats.current.vote_count, i);
  <a href="Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> stats.current.vote_count, test + 1);
  <a href="Vector.md#0x1_Vector_swap_remove">Vector::swap_remove</a>(&<b>mut</b> stats.current.vote_count, i);
  stats.current.total_votes = stats.current.total_votes + 1;
}
</code></pre>



</details>

<a name="0x1_Stats_reconfig"></a>

## Function `reconfig`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_reconfig">reconfig</a>(vm: &signer, set: &vector&lt;address&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_reconfig">reconfig</a>(vm: &signer, set: &vector&lt;address&gt;) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190011));
  <b>let</b> stats = borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(sender);
  // Archive outgoing epoch stats.
  //TODO: limit the size of the history and drop ancient records.
  <a href="Vector.md#0x1_Vector_push_back">Vector::push_back</a>(&<b>mut</b> stats.history, *&stats.current);

  stats.current = <a href="Stats.md#0x1_Stats_blank">blank</a>();

  <a href="Stats.md#0x1_Stats_init_set">init_set</a>(vm, set);
}
</code></pre>



</details>

<a name="0x1_Stats_get_total_votes"></a>

## Function `get_total_votes`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_get_total_votes">get_total_votes</a>(vm: &signer): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_get_total_votes">get_total_votes</a>(vm: &signer): u64 <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190012));
  *&borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(<a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>()).current.total_votes
}
</code></pre>



</details>

<a name="0x1_Stats_get_total_props"></a>

## Function `get_total_props`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_get_total_props">get_total_props</a>(vm: &signer): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_get_total_props">get_total_props</a>(vm: &signer): u64 <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190013));
  *&borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(<a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>()).current.total_props
}
</code></pre>



</details>

<a name="0x1_Stats_get_history"></a>

## Function `get_history`



<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_get_history">get_history</a>(): vector&lt;<a href="Stats.md#0x1_Stats_SetData">Stats::SetData</a>&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_get_history">get_history</a>(): vector&lt;<a href="Stats.md#0x1_Stats_SetData">SetData</a>&gt; <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  *&borrow_global_mut&lt;<a href="Stats.md#0x1_Stats_ValStats">ValStats</a>&gt;(<a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>()).history
}
</code></pre>



</details>

<a name="0x1_Stats_test_helper_inc_vote_addr"></a>

## Function `test_helper_inc_vote_addr`

TEST HELPERS


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_test_helper_inc_vote_addr">test_helper_inc_vote_addr</a>(vm: &signer, node_addr: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Stats.md#0x1_Stats_test_helper_inc_vote_addr">test_helper_inc_vote_addr</a>(vm: &signer, node_addr: address) <b>acquires</b> <a href="Stats.md#0x1_Stats_ValStats">ValStats</a> {
  <b>let</b> sender = <a href="Signer.md#0x1_Signer_address_of">Signer::address_of</a>(vm);
  <b>assert</b>(sender == <a href="CoreAddresses.md#0x1_CoreAddresses_LIBRA_ROOT_ADDRESS">CoreAddresses::LIBRA_ROOT_ADDRESS</a>(), <a href="Errors.md#0x1_Errors_requires_role">Errors::requires_role</a>(190015));

  <b>assert</b>(<a href="Testnet.md#0x1_Testnet_is_testnet">Testnet::is_testnet</a>(), <a href="Errors.md#0x1_Errors_invalid_state">Errors::invalid_state</a>(190015));
  <a href="Stats.md#0x1_Stats_inc_vote">inc_vote</a>(vm, node_addr);
}
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/libra/lip/blob/master/lips/lip-2.md
[ROLE]: https://github.com/libra/lip/blob/master/lips/lip-2.md#roles
[PERMISSION]: https://github.com/libra/lip/blob/master/lips/lip-2.md#permissions
