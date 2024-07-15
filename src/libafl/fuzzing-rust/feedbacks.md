# Feedbacks

A [`Feedback`](https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html) is a
trait implemented by an object that takes as input the state of an 
[`Observer`](https://docs.rs/libafl/latest/libafl/observers/trait.Observer.html) and
determines, after each fuzzing iteration, whether the state of the observer is
*interesting*. This interestingness determination is entirely up to the implementer,
although many common cases are implemented by default.

For example, the
[`AflMapFeedback`](https://docs.rs/libafl/latest/libafl/feedbacks/map/type.AflMapFeedback.html)
implements the interestingness determination used by AFL and AFL++ given the state of a
[`HitcountsMapObserver`](https://docs.rs/libafl/latest/libafl/observers/map/hitcount_map/struct.HitcountsMapObserver.html).

The interestingness determination from each feedback is used to determine whether a
testcase should be kept, and further mutated, or discarded. The 
[`AflMapFeedback`](https://docs.rs/libafl/latest/libafl/feedbacks/map/type.AflMapFeedback.html)
keeps testcases that exercise any new control flow, whether that is exploring a
previously unexplored edge in the CFG or exploring an explored edge a previously un-seen
number of times (for example, an additional loop iteration).