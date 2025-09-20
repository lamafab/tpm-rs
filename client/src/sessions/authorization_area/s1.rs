use crate::sessions::{AuthorizationArea, AuthorizationArea1Plus, NoSession, Session};

impl<T: Session> AuthorizationArea<T, NoSession, NoSession> for T {
    fn decompose_ref(&self) -> (Option<&T>, Option<&NoSession>, Option<&NoSession>) {
        (Some(self), None, None)
    }
    fn decompose_mut(
        &mut self,
    ) -> (
        Option<&mut T>,
        Option<&mut NoSession>,
        Option<&mut NoSession>,
    ) {
        (Some(self), None, None)
    }
}
impl<T: Session> AuthorizationArea1Plus<T, NoSession, NoSession> for T {
    fn decompose_ref(&self) -> (&T, Option<&NoSession>, Option<&NoSession>) {
        (self, None, None)
    }
    fn decompose_mut(&mut self) -> (&mut T, Option<&mut NoSession>, Option<&mut NoSession>) {
        (self, None, None)
    }
}
