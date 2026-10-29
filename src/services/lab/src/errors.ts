// Fixed, non-secret control error results (plan section 5.1). Never carries request or Redis data.
export type ControlErrorResult =
  | 'BAD_VERSION' | 'BAD_MESSAGE' | 'WRONG_RUN' | 'WRONG_CONFIG' | 'WRONG_INCARNATION'
  | 'ILLEGAL_STATE' | 'DEPENDENCY_UNAVAILABLE' | 'FAULTED';

export class LabError extends Error {
  readonly result: ControlErrorResult;
  constructor(result: ControlErrorResult) {
    super(result);
    this.name = 'LabError';
    this.result = result;
  }
}
